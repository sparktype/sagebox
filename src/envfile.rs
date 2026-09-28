// 프로젝트 .envrc/.env의 평문 비밀을 프로젝트 네임스페이스로 옮기고, direnv가 `eval "$(sgb env)"`로 불러오게 하는 모듈
use std::path::Path;

use zeroize::Zeroizing;

use crate::admin;
use crate::import::{Verdict, classify};
use crate::namespace;
use crate::vault::{self, Result, Vault};

/// .envrc에 넣는 줄. 첫 비밀 줄이 있던 자리에 들어가 뒤쪽 줄의 참조 순서를 지킨다.
const EVAL_LINE: &str = "eval \"$(sgb env)\"";

fn valid_var(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `export K=V` 또는 `K=V` 한 줄에서 리터럴 값만 꺼낸다. 셸이 계산하는 값($, 백틱, 공백 등)이면 None.
pub fn parse_line(line: &str) -> Option<(String, String)> {
    let line = line.trim_start();
    let line = line
        .strip_prefix("export ")
        .map(str::trim_start)
        .unwrap_or(line);
    let (var, raw) = line.split_once('=')?;
    if !valid_var(var) {
        return None;
    }
    let raw = raw.trim_end();
    let value = if let Some(inner) = raw.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        // 작은따옴표 안은 그대로다. 다만 안에 작은따옴표가 또 있으면 이어 붙인 식이라 제외한다.
        (!inner.contains('\'')).then_some(inner)?
    } else if let Some(inner) = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        (!inner.contains(['"', '$', '`', '\\'])).then_some(inner)?
    } else {
        let special = |c: char| c.is_whitespace() || "$`\\\"';&|<>()#".contains(c);
        (!raw.contains(special)).then_some(raw)?
    };
    Some((var.to_string(), value.to_string()))
}

/// 디렉터리 이름을 네임스페이스 이름으로 바꾼다(소문자, 허용되지 않는 문자는 `-`, 최대 32자).
pub fn namespace_for(dir: &Path) -> Result<String> {
    let base = dir.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let mut name: String = base
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    name = name
        .trim_start_matches(['-', '_'])
        .chars()
        .take(32)
        .collect();
    namespace::validate(&name).map_err(|_| {
        format!("cannot derive a namespace from {base:?}; add a .sagebox file first")
    })?;
    Ok(name)
}

struct Moved {
    index: usize,
    var: String,
    value: Zeroizing<String>,
    why: &'static str,
}

pub fn import(root: &Path, file: &Path, keep: &[&str], apply: bool) -> Result<()> {
    let file = file.canonicalize()?;
    let project = file.parent().ok_or("file has no directory")?.to_path_buf();
    let text = Zeroizing::new(std::fs::read_to_string(&file)?);
    let lines: Vec<&str> = text.lines().collect();

    let marker = project.join(".sagebox");
    let (ns, has_marker) = if marker.is_file() {
        (
            namespace::parse_file(&std::fs::read_to_string(&marker)?)?,
            true,
        )
    } else {
        (namespace_for(&project)?, false)
    };
    namespace::validate(&ns)?;
    let vault_path = namespace::dir(root, &ns).join("vault");
    let new_ns = !vault_path.exists();

    let mut moved = vec![];
    let mut computed = vec![];
    for (index, line) in lines.iter().enumerate() {
        let Some((var, value)) = parse_line(line) else {
            let t = line.trim_start().trim_start_matches("export ").trim_start();
            if let Some((var, _)) = t.split_once('=').filter(|(v, _)| valid_var(v)) {
                computed.push(var.to_string());
            }
            continue;
        };
        let verdict = if keep.contains(&var.as_str()) {
            Verdict::NotSecret
        } else {
            classify(&var, &value)
        };
        let why = match verdict {
            Verdict::Secret(why) => why,
            Verdict::Unsure => "unsure",
            Verdict::NotSecret => continue,
        };
        moved.push(Moved {
            index,
            var,
            value: Zeroizing::new(value),
            why,
        });
    }

    println!(
        "namespace: {ns}{} (project {})",
        if new_ns {
            " (new: will ask for a new passphrase)"
        } else {
            ""
        },
        project.display()
    );
    for m in &moved {
        let note = if m.why == "unsure" {
            " (use --keep to leave it)"
        } else {
            ""
        };
        println!("  {} -> vault [{}]{note}", m.var, m.why);
    }
    for var in &computed {
        println!("  {var} stays (computed by the shell)");
    }
    if moved.is_empty() {
        println!("no literal secrets found; nothing to do");
        return Ok(());
    }
    if !apply {
        println!("dry run: nothing changed. Re-run with --apply.");
        return Ok(());
    }

    let fill = |v: &mut Vault| -> Result<()> {
        for m in &moved {
            if v.shell_env.contains_key(&m.var) {
                return Err(format!("{} is already exported by namespace {ns}", m.var).into());
            }
            if m.value.contains('\0') {
                return Err(format!("{} contains a NUL byte", m.var).into());
            }
            v.secrets.insert(m.var.clone(), m.value.clone());
            v.shell_env.insert(m.var.clone(), m.var.clone());
        }
        v.trusted.insert(project.display().to_string());
        Ok(())
    };
    crate::create_private_dir(vault_path.parent().ok_or("no namespace dir")?)?;
    if new_ns {
        let pass = admin::read_new_passphrase()?;
        let mut v = Vault::default();
        fill(&mut v)?;
        let (bytes, dek) = vault::create(&v, pass.as_bytes(), vault::DEFAULT_KDF)?;
        let bytes = with_touchid(bytes, &v, &dek);
        vault::write_atomic(&vault_path, &bytes)?;
    } else {
        admin::edit(&vault_path, fill)?;
    }
    if !has_marker {
        std::fs::write(&marker, format!("namespace = \"{ns}\"\n"))?;
    }
    rewrite(&file, &lines, &moved)?;

    println!(
        "moved {} secrets into namespace {ns} and rewrote {}.",
        moved.len(),
        file.display()
    );
    println!(
        "next: run `direnv allow {}` after reviewing the file.",
        project.display()
    );
    if tracked_by_git(&project, &file) {
        println!(
            "warning: {} is tracked by git, so the old values remain in its history: rotate them.",
            file.display()
        );
    } else {
        println!("the old plaintext values may still exist in backups: rotate them if in doubt.");
    }
    Ok(())
}

/// 새 네임스페이스는 `sgb env`가 매번 Touch ID로 확인하도록 SE 슬롯을 바로 켠다(macOS).
#[cfg(target_os = "macos")]
fn with_touchid(bytes: Vec<u8>, v: &Vault, dek: &vault::Dek) -> Vec<u8> {
    let result = vault::Header::parse(&bytes).and_then(|(mut h, _)| {
        crate::touchid::add_slot(&mut h, dek)?;
        vault::seal(&h, v, dek)
    });
    result.unwrap_or_else(|e| {
        eprintln!("sgb: could not enable Touch ID ({e}); `sgb env` will ask for the passphrase");
        bytes
    })
}

#[cfg(not(target_os = "macos"))]
fn with_touchid(bytes: Vec<u8>, _: &Vault, _: &vault::Dek) -> Vec<u8> {
    bytes
}

/// 비밀 줄을 빼고, 첫 비밀 줄 자리에 eval 줄을 넣는다. 파일 권한은 유지한다.
fn rewrite(file: &Path, lines: &[&str], moved: &[Moved]) -> Result<()> {
    let first = moved.iter().map(|m| m.index).min().unwrap_or(0);
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i == first {
            out.push_str(EVAL_LINE);
            out.push('\n');
        }
        if !moved.iter().any(|m| m.index == i) {
            out.push_str(line);
            out.push('\n');
        }
    }
    let perms = std::fs::metadata(file)?.permissions();
    vault::write_atomic(file, out.as_bytes())?;
    std::fs::set_permissions(file, perms)?;
    Ok(())
}

fn tracked_by_git(project: &Path, file: &Path) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(project)
        .args(["ls-files", "--error-unmatch"])
        .arg(file)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg_attr(not(unix), allow(dead_code))]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// `sgb env`: 매번 사용자 확인(Touch ID, 없으면 패스프레이즈)을 거쳐 `export` 문을 출력한다.
/// 데몬 세션을 쓰지 않으므로, 세션이 풀려 있어도 에이전트가 몰래 꺼낼 수 없다.
#[cfg(unix)]
pub fn export(ns: &namespace::Ns, allow_tty: bool) -> Result<()> {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() && !allow_tty {
        return Err("refusing to print secrets to a terminal; use it as `eval \"$(sgb env)\"` in .envrc (or pass --print)".into());
    }
    let vault_path = ns.dir.join("vault");
    let file = std::fs::read(&vault_path)?;
    let dek = fresh_dek(ns, &vault_path, &file)?;
    let (_, v) = vault::open(&file, &dek)?;
    v.check_project(
        ns.project
            .as_ref()
            .map(|p| p.display().to_string())
            .as_deref(),
    )?;
    v.check_expiry(v.shell_env.values(), vault::unix_now())?;
    for (var, secret) in &v.shell_env {
        let value = v
            .secrets
            .get(secret)
            .ok_or(format!("missing secret {secret}"))?;
        println!("export {var}={}", shell_quote(value));
    }
    Ok(())
}

/// 이번 호출만을 위해 DEK를 푼다. SE 슬롯이 있으면 시스템 대화상자, 없으면 패스프레이즈.
#[cfg(unix)]
fn fresh_dek(ns: &namespace::Ns, vault_path: &Path, file: &[u8]) -> Result<vault::Dek> {
    let no_gui = crate::debug::flag("SAGEBOX_NO_GUI");
    let project = std::env::current_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    let what = format!(
        "export secrets of namespace \"{}\" to the shell\nproject: {project}",
        ns.name
    );
    #[cfg(target_os = "macos")]
    if !no_gui {
        match crate::touchid::unlock(vault_path, &what) {
            Ok(Some(dek)) => return Ok(dek),
            Ok(None) => {}
            Err(e) => eprintln!("sgb: Touch ID failed ({e}); falling back to the passphrase"),
        }
    }
    let _ = vault_path; // macOS 외에서는 SE 경로가 없어 쓰이지 않는다
    let pass = if no_gui {
        admin::read_secret("passphrase: ")?
    } else {
        crate::prompt::ask(&format!("Unlock sagebox to {what}"))?
    };
    let (h, _) = vault::Header::parse(file)?;
    h.unlock_passphrase(pass.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_lines() {
        let ok = [
            (
                "export OPENAI_API_KEY=sk-abc123",
                ("OPENAI_API_KEY", "sk-abc123"),
            ),
            ("TOKEN='a b$c'", ("TOKEN", "a b$c")),
            ("  export  X=\"plain value\"", ("X", "plain value")),
            ("EMPTY=", ("EMPTY", "")),
        ];
        for (line, (k, v)) in ok {
            assert_eq!(
                parse_line(line),
                Some((k.to_string(), v.to_string())),
                "{line}"
            );
        }
        for line in [
            "export PATH=$PATH:/bin",
            "URL=\"https://$HOST/x\"",
            "X=`cat key`",
            "X=$(pass show x)",
            "X=a b",
            "layout python",
            "dotenv .env.local",
            "# comment",
            "1BAD=x",
            "X='it'\"'\"'s'",
        ] {
            assert_eq!(parse_line(line), None, "{line}");
        }
    }

    #[test]
    fn namespace_from_dir() {
        assert_eq!(namespace_for(Path::new("/w/Richell")).unwrap(), "richell");
        assert_eq!(
            namespace_for(Path::new("/w/gemma4-12b-it-sparkman")).unwrap(),
            "gemma4-12b-it-sparkman"
        );
        assert_eq!(namespace_for(Path::new("/w/pdf_kor")).unwrap(), "pdf_kor");
        assert_eq!(
            namespace_for(Path::new("/w/My Project.v2")).unwrap(),
            "my-project-v2"
        );
        assert!(namespace_for(Path::new("/w/한글")).is_err());
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("a'b c"), "'a'\"'\"'b c'");
    }
}
