// 터미널이 없는 exec(에이전트가 띄운 MCP 서버)에서 OS 대화상자로 패스프레이즈를 묻는 GUI 프롬프트
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use crate::vault::Result;

/// 대화상자를 띄워 패스프레이즈를 받는다. 취소하거나 쓸 수 있는 도구가 없으면 Err.
pub fn ask(message: &str) -> Result<Zeroizing<String>> {
    if std::env::var_os("SAGEBOX_NO_GUI").is_some() {
        return Err("GUI prompt disabled by SAGEBOX_NO_GUI".into());
    }
    #[cfg(target_os = "macos")]
    return osascript(message);
    #[cfg(not(target_os = "macos"))]
    {
        let has_display = ["DISPLAY", "WAYLAND_DISPLAY"]
            .iter()
            .any(|v| std::env::var_os(v).is_some());
        if has_display {
            if let Some(r) = run(Command::new("zenity").args([
                "--entry",
                "--hide-text",
                "--title=sagebox",
                &format!("--text={message}"),
            ])) {
                return r;
            }
            if let Some(r) =
                run(Command::new("kdialog").args(["--title", "sagebox", "--password", message]))
            {
                return r;
            }
        }
        pinentry(message)
    }
}

#[cfg(target_os = "macos")]
fn osascript(message: &str) -> Result<Zeroizing<String>> {
    let quoted = message.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        r#"display dialog "{quoted}" default answer "" with hidden answer with title "sagebox" with icon caution giving up after 120"#
    );
    run(Command::new("osascript").args(["-e", &script, "-e", "text returned of result"]))
        .unwrap_or_else(|| Err("osascript not available".into()))
}

/// 도구가 없으면 None, 있으면 입력값 또는 취소 오류.
fn run(cmd: &mut Command) -> Option<Result<Zeroizing<String>>> {
    let out = match cmd.stdin(Stdio::null()).stderr(Stdio::null()).output() {
        Ok(out) => out,
        Err(_) => return None,
    };
    let text = Zeroizing::new(String::from_utf8_lossy(&out.stdout).into_owned());
    let mut stdout = Zeroizing::new(out.stdout);
    stdout.iter_mut().for_each(|b| *b = 0);
    let pass = Zeroizing::new(text.trim_end_matches(['\r', '\n']).to_string());
    Some(if out.status.success() && !pass.is_empty() {
        Ok(pass)
    } else {
        Err("passphrase prompt cancelled".into())
    })
}

/// Assuan 프로토콜로 pinentry와 대화한다. GnuPG가 설치된 Linux에 흔히 있다.
#[cfg(not(target_os = "macos"))]
fn pinentry(message: &str) -> Result<Zeroizing<String>> {
    use std::io::{BufRead, BufReader, Write};
    let enc = |s: &str| {
        s.replace('%', "%25")
            .replace('\n', "%0A")
            .replace('\r', "%0D")
    };
    let mut child = Command::new("pinentry")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "no GUI prompt available (install zenity, kdialog or pinentry)")?;
    let script = format!(
        "SETTITLE sagebox\nSETDESC {}\nSETPROMPT Passphrase:\nGETPIN\nBYE\n",
        enc(message)
    );
    child
        .stdin
        .take()
        .ok_or("pinentry stdin")?
        .write_all(script.as_bytes())?;
    let mut pass = None;
    for line in BufReader::new(child.stdout.take().ok_or("pinentry stdout")?).lines() {
        let line = Zeroizing::new(line?);
        if let Some(data) = line.strip_prefix("D ") {
            pass = Some(Zeroizing::new(
                data.replace("%0A", "\n")
                    .replace("%0D", "\r")
                    .replace("%25", "%"),
            ));
        }
    }
    let _ = child.wait();
    pass.filter(|p| !p.is_empty())
        .ok_or_else(|| "passphrase prompt cancelled".into())
}
