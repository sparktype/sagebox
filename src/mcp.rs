// 프로필 생성과 Claude Code 등록을 한 번에 하는 `sgb mcp add`. 볼트에 없는 비밀은 그 자리에서 입력받는다.
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use serde_json::json;

use crate::admin;
use crate::import::resolve_command;
use crate::namespace;
use crate::vault::{Profile, Result};

pub fn add(
    vault_path: &Path,
    ns: &str,
    server: &str,
    env: BTreeMap<String, String>,
    command: Vec<String>,
    scope: &str,
) -> Result<()> {
    if !["local", "user", "project"].contains(&scope) {
        return Err(format!("--scope must be local, user or project (got {scope})").into());
    }
    let (bin, args) = command.split_first().ok_or("missing command after --")?;
    // PATH 조작으로 다른 실행 파일이 끼어들지 않도록 지금 위치를 절대경로로 고정한다.
    let mut argv = vec![resolve_command(bin)?.display().to_string()];
    argv.extend(args.iter().cloned());
    for var in env.keys() {
        admin::check_env_name(var)?;
    }

    admin::edit(vault_path, |v| {
        if v.profiles.contains_key(server) {
            return Err(format!(
                "profile {server} already exists (remove it with `sgb profile rm {server}`)"
            )
            .into());
        }
        for secret in env.values() {
            if !v.secrets.contains_key(secret) {
                let value = admin::read_secret(&format!("value for new secret {secret}: "))?;
                if value.contains('\0') {
                    return Err("secret value must not contain NUL bytes".into());
                }
                v.secrets.insert(secret.clone(), value);
            }
        }
        v.profiles.insert(
            server.into(),
            Profile {
                command: argv.clone(),
                env: env.clone(),
            },
        );
        Ok(())
    })?;
    println!("profile {server} -> {}", argv.join(" "));

    let sgb = std::env::current_exe()?.display().to_string();
    let mut exec_args: Vec<String> = vec![];
    if ns != namespace::DEFAULT {
        exec_args.extend(["--ns".into(), ns.into()]);
    }
    exec_args.extend(["exec".into(), server.into()]);

    let registered = Command::new("claude")
        .args(["mcp", "add", "-s", scope, server, "--", &sgb])
        .args(&exec_args)
        .status();
    match registered {
        Ok(st) if st.success() => println!("registered with Claude Code (scope: {scope})"),
        Ok(st) => println!(
            "`claude mcp add` failed ({st}). If {server} is already registered, run `claude mcp remove {server} -s {scope}` and register it again, or use the config below."
        ),
        Err(_) => println!("claude CLI not found; add the config below to your MCP client."),
    }
    let snippet = json!({ server: { "command": sgb, "args": exec_args } });
    println!(
        "config for other MCP clients:\n{}",
        serde_json::to_string_pretty(&snippet)?
    );
    Ok(())
}
