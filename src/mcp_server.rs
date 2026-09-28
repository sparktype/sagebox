// 에이전트가 비밀 이름·프로필·잠금 상태를 조회하는 stdio MCP 서버 `sgb mcp serve`. 비밀 값은 절대 돌려주지 않는다.
use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::client;
use crate::daemon::{Request, Response};
use crate::namespace::Ns;
use crate::vault::Result;

/// 클라이언트가 버전을 보내지 않았을 때 쓰는 값.
const PROTOCOL: &str = "2025-06-18";

/// 줄 단위 JSON-RPC 2.0. 데몬은 띄우지 않고, 이미 풀린 세션에만 묻는다.
pub fn serve(ns: &Ns) -> Result<()> {
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

fn handle(ns: &Ns, msg: &Value) -> std::result::Result<Value, (i32, String)> {
    let params = &msg["params"];
    match msg["method"].as_str().unwrap_or("") {
        "initialize" => Ok(json!({
            "protocolVersion": params["protocolVersion"].as_str().unwrap_or(PROTOCOL),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "sagebox", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "sagebox keeps the user's API keys and passwords. These tools show secret names, profiles and lock status only; secret values are never returned. To give an MCP server a secret, ask the user to run `sgb mcp add <server> --env VAR=secret -- <command>`.",
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": [
            {
                "name": "status",
                "description": "Whether this project's sagebox namespace is unlocked, and how many MCP servers currently hold secrets from it.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "list",
                "description": "Secret names (with expiry dates) and profiles (MCP servers: env var -> secret name, command) in this project's sagebox namespace. Never returns secret values. Needs an unlocked session.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]})),
        "tools/call" => {
            let result = match params["name"].as_str().unwrap_or("") {
                "status" => status(ns),
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

fn status(ns: &Ns) -> Result<String> {
    Ok(match client::query(ns, &Request::Status)? {
        None
        | Some(Response::Status {
            unlocked: false, ..
        }) => locked(ns),
        Some(Response::Status {
            leases,
            absolute_left_secs,
            ..
        }) => format!(
            "namespace {} is unlocked ({leases} active servers, hard lock in {}m)",
            ns.name,
            absolute_left_secs / 60
        ),
        _ => return Err("unexpected response".into()),
    })
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
