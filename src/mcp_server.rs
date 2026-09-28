// 에이전트가 비밀 이름·프로필·잠금 상태를 조회하는 stdio MCP 서버 `sagebox mcp serve`. 비밀 값은 절대 돌려주지 않는다.
use std::io::{BufRead, Read, Write};

use serde_json::{Value, json};

use crate::client;
use crate::daemon::{Request, Response};
use crate::namespace::Ns;
use crate::vault::Result;

/// 클라이언트가 버전을 보내지 않았을 때 쓰는 값.
const PROTOCOL: &str = "2025-06-18";

/// 줄 단위 JSON-RPC 2.0. 살아 있는 동안 데몬에 임대를 잡아 `sagebox run`을 허용한다.
/// 조회 도구는 잠금을 풀지 않고, 이미 풀린 세션에만 묻는다.
pub fn serve(ns: &Ns) -> Result<()> {
    if ns.dir.join("vault").exists() {
        let ns = ns.clone();
        std::thread::spawn(move || hold_lease(&ns));
    }
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}});
                writeln!(out, "{err}")?;
                out.flush()?;
                continue;
            }
        };
        // id가 없으면 알림이라 답하지 않는다.
        let Some(id) = msg.get("id").cloned() else {
            continue;
        };
        let reply = match handle(ns, &msg) {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, message)) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
            }
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
    Ok(())
}

/// 임대를 잡고 있다가 데몬이 끝나면(lock·화면 잠금·8시간) 다시 잡는다. 새 데몬은 잠긴 채로 뜬다.
/// 이 프로세스가 끝나면 소켓이 닫혀 임대도 끝난다.
fn hold_lease(ns: &Ns) {
    loop {
        match client::attach(ns) {
            Ok(mut s) => {
                let mut buf = [0u8; 64];
                while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
            }
            Err(e) => crate::debug::log(format_args!("mcp serve: attach failed: {e}")),
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

fn handle(ns: &Ns, msg: &Value) -> std::result::Result<Value, (i32, String)> {
    let params = &msg["params"];
    match msg["method"].as_str().unwrap_or("") {
        "initialize" => Ok(json!({
            "protocolVersion": params["protocolVersion"].as_str().unwrap_or(PROTOCOL),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "sagebox", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "sagebox keeps the user's API keys and passwords. The `list` tool shows secret names, profiles and lock status only; secret values are never returned. To give an MCP server a secret, ask the user to run `sagebox mcp add <server> --env VAR=secret -- <command>`. To run or debug this project with its env (replacing .envrc), use `sagebox run -- <command>` in the shell; it works only while this server is running.",
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": [
            {
                "name": "list",
                "description": "Secret names (with expiry dates) and profiles (MCP servers: env var -> secret name, command) in this project's sagebox namespace. Never returns secret values. If the namespace is locked, says so and how to unlock it.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]})),
        "tools/call" => {
            let result = match params["name"].as_str().unwrap_or("") {
                "list" => list(ns),
                other => return Err((-32602, format!("unknown tool {other}"))),
            };
            Ok(match result {
                Ok(text) => json!({"content": [{"type": "text", "text": text}]}),
                Err(e) => {
                    json!({"content": [{"type": "text", "text": e.to_string()}], "isError": true})
                }
            })
        }
        other => Err((-32601, format!("method not found: {other}"))),
    }
}

fn locked(ns: &Ns) -> String {
    format!(
        "namespace {} is locked. Ask the user to run `{}` in a terminal (Touch ID or passphrase).",
        ns.name,
        client::unlock_hint(ns)
    )
}

fn list(ns: &Ns) -> Result<String> {
    let project = ns.project.as_ref().map(|p| p.display().to_string());
    Ok(match client::query(ns, &Request::List { project })? {
        None | Some(Response::Locked) => locked(ns),
        Some(Response::List { mut inventory }) => {
            inventory["namespace"] = json!(ns.name);
            serde_json::to_string_pretty(&inventory)?
        }
        _ => return Err("unexpected response".into()),
    })
}
