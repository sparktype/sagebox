// MCP 설정(mcpServers)의 평문 비밀을 볼트로 옮기고, 설정을 `sgb exec <프로필>`로 바꿔 쓰는 가져오기
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::admin;
use crate::vault::{self, Profile, Result};

#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// 비밀이다. 이유는 출력용(값은 절대 담지 않는다).
    Secret(&'static str),
    NotSecret,
    /// 규칙으로 판단이 안 된다. 기본은 비밀로 취급한다.
    Unsure,
}

const TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "github_pat_",
    "glpat-",
    "sk-",
    "sk_live_",
    "rk_live_",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "eyJ",
    "npm_",
    "hf_",
];
const SECRET_NAME_PARTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PWD",
    "APIKEY",
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "COOKIE",
    "SESSION",
    "AUTH",
];

/// 변수 이름과 값으로 비밀 여부를 판단한다. 값은 이 프로세스 밖으로 나가지 않는다.
pub fn classify(name: &str, value: &str) -> Verdict {
    let upper = name.to_ascii_uppercase();
    if TOKEN_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return Verdict::Secret("token prefix");
    }
    if let Some((_, rest)) = value.split_once("://") {
        let authority = rest.split('/').next().unwrap_or("");
        if let Some((userinfo, _)) = authority.rsplit_once('@') {
            return if userinfo.contains(':') {
                Verdict::Secret("URL with password")
            } else {
                Verdict::Unsure // 예: Sentry DSN처럼 사용자 자리에 키가 들어간 URL
            };
        }
        if rest.starts_with("hooks.slack.com/") || rest.contains("/api/webhooks/") {
            return Verdict::Secret("webhook URL");
        }
    }
    let excluded = upper.contains("PUBLIC")
        || ["_PATH", "_FILE", "_DIR"]
            .iter()
            .any(|s| upper.ends_with(s));
    if !excluded && SECRET_NAME_PARTS.iter().any(|p| upper.contains(p)) {
        return Verdict::Secret("name");
    }
    let plain = value.len() < 16
        || value.contains("://")
        || value.starts_with('/')
        || value.starts_with('~')
        || value.contains(char::is_whitespace);
    if plain {
        Verdict::NotSecret
    } else {
        Verdict::Unsure // 긴 무작위 문자열인데 이름으로는 모르겠다
    }
}

/// PATH에서 실행 파일을 찾아 절대경로로 고정한다.
pub(crate) fn resolve_command(cmd: &str) -> Result<PathBuf> {
    let p = Path::new(cmd);
    if p.is_absolute() {
        return Ok(p.to_path_buf());
    }
    if cmd.contains('/') {
        return Err(format!("relative command path {cmd:?} is not supported").into());
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(cmd))
        .find(|c| c.is_file())
        .ok_or_else(|| format!("command {cmd:?} not found in PATH").into())
}

struct Plan {
    server: String,
    command: Vec<String>,
    /// (환경변수, 볼트 비밀 이름, 이유)
    moved: Vec<(String, String, &'static str)>,
    kept: Vec<String>,
}

fn plan(config: &Value, keep: &[&str], sgb: &Path) -> Result<(Vec<Plan>, Vec<String>)> {
    let servers = config["mcpServers"]
        .as_object()
        .ok_or("no \"mcpServers\" object in this file")?;
    let (mut plans, mut skipped) = (vec![], vec![]);
    for (server, def) in servers {
        let cmd = def["command"].as_str().unwrap_or_default();
        if Path::new(cmd) == sgb || Path::new(cmd).file_name() == Some("sgb".as_ref()) {
            skipped.push(format!("{server}: already managed by sgb"));
            continue;
        }
        let env = def["env"].as_object();
        let (mut moved, mut kept) = (vec![], vec![]);
        for (var, value) in env.into_iter().flatten() {
            let value = value.as_str().unwrap_or_default();
            let verdict = if keep.contains(&var.as_str()) {
                Verdict::NotSecret
            } else {
                classify(var, value)
            };
            match verdict {
                Verdict::Secret(why) => moved.push((var.clone(), format!("{server}.{var}"), why)),
                Verdict::Unsure => moved.push((var.clone(), format!("{server}.{var}"), "unsure")),
                Verdict::NotSecret => kept.push(var.clone()),
            }
        }
        if moved.is_empty() {
            skipped.push(format!("{server}: no secrets, unchanged"));
            continue;
        }
        let mut command = vec![resolve_command(cmd)?.display().to_string()];
        for a in def["args"].as_array().into_iter().flatten() {
            command.push(a.as_str().ok_or("non-string arg")?.to_string());
        }
        plans.push(Plan {
            server: server.clone(),
            command,
            moved,
            kept,
        });
    }
    Ok((plans, skipped))
}

/// 기본은 미리보기. apply면 볼트와 설정 파일을 바꾼다. ns_args는 exec에 붙일 `--ns <이름>`.
pub fn run(
    vault_path: &Path,
    file: &Path,
    keep: &[&str],
    apply: bool,
    ns_args: &[String],
) -> Result<()> {
    let text = Zeroizing::new(std::fs::read_to_string(file)?);
    // ponytail: serde_json Value 안의 평문 값은 drop 때 지워지지 않는다. 일회성 관리 명령이라 프로세스 종료로 갈음한다
    let mut config: Value = serde_json::from_str(&text)?;
    let sgb = std::env::current_exe()?;
    let (plans, skipped) = plan(&config, keep, &sgb)?;

    for p in &plans {
        println!("{}: profile -> {}", p.server, p.command.join(" "));
        for (var, secret, why) in &p.moved {
            let note = if *why == "unsure" {
                " (unsure; use --keep to leave it)"
            } else {
                ""
            };
            println!("  {var} -> secret {secret} [{why}]{note}");
        }
        for var in &p.kept {
            println!("  {var} stays in config");
        }
    }
    for s in &skipped {
        println!("{s}");
    }
    if plans.is_empty() {
        return Ok(());
    }
    if !apply {
        println!(
            "dry run: nothing changed. Re-run with --apply to import (needs the namespace passphrase)."
        );
        return Ok(());
    }

    admin::edit(vault_path, |v| {
        // 쓰기 전에 충돌부터 전부 확인한다.
        for p in &plans {
            if v.profiles.contains_key(&p.server) {
                return Err(format!("profile {} already exists", p.server).into());
            }
            for (var, secret, _) in &p.moved {
                admin::check_env_name(var)?;
                if v.secrets.contains_key(secret) {
                    return Err(format!("secret {secret} already exists").into());
                }
            }
        }
        for p in &plans {
            let def = &config["mcpServers"][&p.server];
            let mut env = BTreeMap::new();
            for (var, secret, _) in &p.moved {
                let value = def["env"][var].as_str().unwrap_or_default();
                if value.contains('\0') {
                    return Err(format!("{var} contains a NUL byte").into());
                }
                v.secrets
                    .insert(secret.clone(), Zeroizing::new(value.to_string()));
                env.insert(var.clone(), secret.clone());
            }
            v.profiles.insert(
                p.server.clone(),
                Profile {
                    command: p.command.clone(),
                    env,
                },
            );
        }
        Ok(())
    })?;

    for p in &plans {
        let def = &mut config["mcpServers"][&p.server];
        let mut args = ns_args.to_vec();
        args.extend(["exec".to_string(), p.server.clone()]);
        def["command"] = json!(sgb.display().to_string());
        def["args"] = json!(args);
        if let Some(env) = def["env"].as_object_mut() {
            for (var, _, _) in &p.moved {
                env.remove(var);
            }
            if env.is_empty() {
                def.as_object_mut().map(|o| o.remove("env"));
            }
        }
    }
    let perms = std::fs::metadata(file)?.permissions();
    let out = Zeroizing::new(serde_json::to_string_pretty(&config)? + "\n");
    vault::write_atomic(file, out.as_bytes())?;
    std::fs::set_permissions(file, perms)?;
    let n: usize = plans.iter().map(|p| p.moved.len()).sum();
    println!(
        "imported {n} secrets and rewrote {}. The old plaintext values may still exist in git history, backups or shell history: rotate them.",
        file.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_rules() {
        use Verdict::*;
        let cases = [
            (
                "GITHUB_TOKEN",
                "ghp_FAKE_test_value",
                Secret("token prefix"),
            ),
            ("X", "xoxb-1234-5678-abcdef", Secret("token prefix")),
            (
                "DATABASE_URL",
                "postgres://app:s3cret@db:5432/app",
                Secret("URL with password"),
            ),
            ("DATABASE_URL", "postgres://db:5432/app", NotSecret),
            (
                "SLACK_WEBHOOK_URL",
                "https://hooks.slack.com/services/T0/B0/xyz",
                Secret("webhook URL"),
            ),
            (
                "SENTRY_DSN",
                "https://abc123@o1.ingest.sentry.io/42",
                Unsure,
            ),
            ("NOTION_API_KEY", "short", Secret("name")),
            ("PUBLIC_KEY_PATH", "/home/me/.ssh/id.pub", NotSecret),
            ("KEYBOARD_LAYOUT", "us", NotSecret),
            ("LOG_LEVEL", "debug", NotSecret),
            ("SOMETHING", "q8Zr1xV0pL3mN7tK2wY9", Unsure),
        ];
        for (name, value, want) in cases {
            assert_eq!(classify(name, value), want, "{name}");
        }
    }
}
