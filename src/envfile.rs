// 프로젝트 .envrc/.env의 평문 비밀을 프로젝트 네임스페이스로 옮겨 `sagebox run`이 넣게 하고, cd 때 검사하는 셸 훅을 제공하는 모듈
use std::path::Path;

use zeroize::Zeroizing;

use crate::admin;
use crate::import::{Verdict, classify};
use crate::namespace;
use crate::vault::{self, Result, Vault};

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

/// 옮길 비밀 줄과, 셸이 계산하는 값이라 남겨 두는 변수 이름.
fn scan(lines: &[&str], keep: &[&str]) -> (Vec<Moved>, Vec<String>) {
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
    (moved, computed)
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

    let (moved, computed) = scan(&lines, keep);

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

    let original = text.clone();
    let original_perms = std::fs::metadata(&file)?.permissions();
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
    if ns != namespace::DEFAULT {
        crate::create_private_dir(&root.join("ns"))?;
    }
    crate::create_private_dir(vault_path.parent().ok_or("no namespace dir")?)?;
    let mut source_written = false;
    let mut marker_created = false;
    let import_result = if new_ns {
        admin::with_vault_lock(&vault_path, || {
            if vault_path.exists() {
                return Err(format!(
                    "{} was created concurrently; retry the import",
                    vault_path.display()
                )
                .into());
            }
            let pass = admin::read_new_passphrase()?;
            let mut v = Vault::default();
            fill(&mut v)?;
            if !has_marker {
                vault::write_atomic(&marker, format!("namespace = \"{ns}\"\n").as_bytes())?;
                marker_created = true;
            }
            // `.envrc`에서 먼저 평문을 없앤다. 뒤의 볼트 저장이 전원 손실로 끝나도
            // 평문 비밀이 다시 노출되는 것보다, 설정이 잠시 동작하지 않는 쪽을 택한다.
            rewrite(&file, &lines, &moved, &mut source_written)?;
            let (bytes, dek) = vault::create(&v, pass.as_bytes(), vault::DEFAULT_KDF)?;
            let bytes = with_touchid(bytes, &v, &dek);
            vault::write_atomic(&vault_path, &bytes)
        })
    } else {
        admin::edit(&vault_path, |v| {
            fill(v)?;
            rewrite(&file, &lines, &moved, &mut source_written)
        })
    };
    if let Err(e) = import_result {
        if source_written {
            let restore = || -> Result<()> {
                vault::write_atomic(&file, original.as_bytes())?;
                std::fs::set_permissions(&file, original_perms)?;
                Ok(())
            };
            if let Err(restore) = restore() {
                return Err(format!(
                    "{e}; also failed to restore the original environment file: {restore}"
                )
                .into());
            }
        }
        if marker_created {
            let _ = std::fs::remove_file(&marker);
        }
        return Err(e);
    }

    println!(
        "moved {} secrets into namespace {ns} and rewrote {}.",
        moved.len(),
        file.display()
    );
    println!(
        "next: run debug commands as `sagebox run -- <command>` in {} (works only while Claude Code with the sagebox MCP server is running).",
        project.display()
    );
    println!(
        "if direnv still loads the remaining lines, run `direnv allow` after reviewing the file."
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

/// `eval "$(sagebox zsh)"`용 스크립트. 디렉터리에 들어갈 때 `hook check`를 부르고,
/// 거절한 디렉터리는 그 셸에서 다시 묻지 않는다.
pub fn hook_script(shell: &str) -> Result<String> {
    let exe = shell_quote(&std::env::current_exe()?.display().to_string());
    let check = format!(
        r#"_sagebox_hook() {{
  [[ -f .envrc || -f .env ]] || return 0
  [[ ":${{_sagebox_skip-}}:" == *":$PWD:"* ]] && return 0
  {exe} hook check || _sagebox_skip="${{_sagebox_skip-}}:$PWD"
}}
"#
    );
    // zsh는 direnv보다 먼저 돌도록 chpwd 맨 앞에 넣는다. 시작 디렉터리 검사는 셸 초기화 중이 아니라
    // 첫 프롬프트 직전에 한 번 한다(p10k instant prompt는 초기화 중 입출력을 허용하지 않는다).
    // bash는 direnv hook 줄 뒤에 두면 앞에 붙는다.
    let install = match shell {
        "zsh" => {
            "chpwd_functions=(_sagebox_hook ${chpwd_functions[@]})\n_sagebox_first() { precmd_functions=(${precmd_functions:#_sagebox_first}); _sagebox_hook; }\nprecmd_functions+=(_sagebox_first)\n"
        }
        "bash" => {
            "_sagebox_prompt() { [[ \"$PWD\" == \"${_sagebox_last-}\" ]] || { _sagebox_last=$PWD; _sagebox_hook; }; }\nPROMPT_COMMAND=\"_sagebox_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}\"\n"
        }
        _ => return Err(format!("unsupported shell {shell} (use zsh or bash)").into()),
    };
    Ok(check + install)
}

/// 현재 디렉터리의 .envrc/.env에 평문 비밀이 있으면 이름을 보여 주고 정리할지 묻는다.
/// 거절하거나 정리하지 못하면 Err라 셸 훅이 그 디렉터리를 기억한다.
pub fn hook_check(root: &Path) -> Result<()> {
    for name in [".envrc", ".env"] {
        let file = Path::new(name);
        if !file.is_file() {
            continue;
        }
        let text = Zeroizing::new(std::fs::read_to_string(file)?);
        let lines: Vec<&str> = text.lines().collect();
        let (moved, _) = scan(&lines, &[]);
        if moved.is_empty() {
            continue;
        }
        eprintln!("sagebox: {name} has plaintext secrets:");
        for m in &moved {
            eprintln!("  {} [{}]", m.var, m.why);
        }
        eprint!("move them into the vault and remove them from {name}? [y/N] ");
        // 다른 프롬프트처럼 stdin에서 한 줄 읽는다. EOF면 거절로 본다.
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            return Err(format!(
                "left {name} unchanged; run `sagebox import-env {name} --apply` (use --keep VAR for false positives)"
            )
            .into());
        }
        import(root, file, &[], true)?;
    }
    Ok(())
}

/// 새 네임스페이스는 `sagebox run`이 Touch ID로 확인하도록 SE 슬롯을 바로 켠다(macOS).
#[cfg(target_os = "macos")]
fn with_touchid(bytes: Vec<u8>, v: &Vault, dek: &vault::Dek) -> Vec<u8> {
    let result = vault::Header::parse(&bytes).and_then(|(mut h, _)| {
        crate::touchid::add_slot(&mut h, dek)?;
        vault::seal(&h, v, dek)
    });
    result.unwrap_or_else(|e| {
        eprintln!(
            "sagebox: could not enable Touch ID ({e}); unlocking will ask for the passphrase"
        );
        bytes
    })
}

#[cfg(not(target_os = "macos"))]
fn with_touchid(bytes: Vec<u8>, _: &Vault, _: &vault::Dek) -> Vec<u8> {
    bytes
}

/// 비밀 줄만 뺀다. 비밀은 `sagebox run`이 넣는다. 파일 권한은 유지한다.
fn rewrite(file: &Path, lines: &[&str], moved: &[Moved], written: &mut bool) -> Result<()> {
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if !moved.iter().any(|m| m.index == i) {
            out.push_str(line);
            out.push('\n');
        }
    }
    let perms = std::fs::metadata(file)?.permissions();
    vault::write_atomic(file, out.as_bytes())?;
    *written = true;
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

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
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
