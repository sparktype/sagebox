// 데몬을 필요할 때 띄우고 unlock/lock/status/exec를 요청하며, exec는 임대 소켓을 물려준 채 execve하는 클라이언트
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::admin::read_secret;
use crate::daemon::{Request, Response, recv, send};
use crate::namespace::{self, Ns};
use crate::prompt;
use crate::vault::Result;

/// 데몬에 연결한다. autostart면 없을 때 띄우고 소켓이 생길 때까지 기다린다.
fn connect(ns: &Ns, autostart: bool) -> Result<Option<UnixStream>> {
    let sock = ns.dir.join("sock");
    if let Ok(s) = UnixStream::connect(&sock) {
        return Ok(Some(s));
    }
    if !autostart {
        return Ok(None);
    }
    // Unix 소켓 경로 한도(macOS 104바이트, Linux 108바이트). 넘으면 데몬이 bind에 실패하고 조용히 끝난다.
    let len = sock.as_os_str().len();
    if len > 103 {
        return Err(format!(
            "socket path is too long ({len} bytes, max 103): {}; set SAGEBOX_HOME to a shorter directory",
            sock.display()
        )
        .into());
    }
    crate::debug::log(format_args!(
        "no daemon at {}; spawning one",
        sock.display()
    ));
    spawn_daemon(&ns.name)?;
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(20));
        if let Ok(s) = UnixStream::connect(&sock) {
            return Ok(Some(s));
        }
    }
    Err("daemon did not start".into())
}

/// double fork + setsid로 데몬을 띄운다. exec 클라이언트는 곧 MCP 서버로 바뀌어
/// 자식을 wait하지 않으므로, 데몬을 init에 입양시켜 좀비가 남지 않게 한다.
fn spawn_daemon(ns: &str) -> Result<()> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.args(["--ns", ns, "daemon"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: fork 이후 자식에서는 async-signal-safe 함수(fork, setsid, _exit)만 호출한다.
    unsafe {
        cmd.pre_exec(|| match libc::fork() {
            -1 => Err(std::io::Error::last_os_error()),
            0 => {
                libc::setsid();
                Ok(())
            }
            _ => libc::_exit(0),
        });
    }
    cmd.spawn()?.wait()?;
    Ok(())
}

/// 이 네임스페이스를 푸는 명령. default가 아니면 --ns를 붙인다.
pub(crate) fn unlock_hint(ns: &Ns) -> String {
    if ns.name == namespace::DEFAULT {
        "sgb unlock".into()
    } else {
        format!("sgb --ns {} unlock", ns.name)
    }
}

fn request(s: &mut UnixStream, req: &Request) -> Result<Response> {
    send(s, req)?;
    match recv(s)? {
        Response::Error { message } => Err(message.into()),
        resp => Ok(resp),
    }
}

/// 데몬을 띄우지 않고 묻는다. 데몬이 없으면(= 잠김) None.
pub(crate) fn query(ns: &Ns, req: &Request) -> Result<Option<Response>> {
    let Some(mut s) = connect(ns, false)? else {
        return Ok(None);
    };
    request(&mut s, req).map(Some)
}

fn unlock_with(ns: &Ns, passphrase: zeroize::Zeroizing<String>) -> Result<()> {
    let mut s = connect(ns, true)?.ok_or("daemon unavailable")?;
    request(&mut s, &Request::Unlock { passphrase })?;
    Ok(())
}

/// Secure Enclave 슬롯이 있으면 시스템 대화상자(Touch ID·Watch·로그인 암호)로 푼다.
/// 슬롯이 없거나 취소·실패하면 false를 돌려주고, 호출한 쪽이 패스프레이즈로 넘어간다.
#[cfg(target_os = "macos")]
fn try_touchid(ns: &Ns, reason: &str) -> bool {
    if crate::debug::flag("SAGEBOX_NO_GUI") {
        return false;
    }
    let result = crate::touchid::unlock(&ns.dir.join("vault"), reason).and_then(|dek| {
        let Some(dek) = dek else { return Ok(false) };
        let mut s = connect(ns, true)?.ok_or("daemon unavailable")?;
        request(&mut s, &Request::UnlockKey { dek })?;
        Ok(true)
    });
    crate::debug::log(format_args!("Touch ID unlock for {}: {result:?}", ns.name));
    result.unwrap_or_else(|e| {
        eprintln!("sgb: Touch ID unlock failed ({e}); falling back to the passphrase");
        false
    })
}

#[cfg(not(target_os = "macos"))]
fn try_touchid(_: &Ns, _: &str) -> bool {
    false
}

/// passphrase_only가 아니면 Touch ID를 먼저 시도한다.
pub fn unlock(ns: &Ns, passphrase_only: bool) -> Result<()> {
    let reason = format!("unlock sagebox namespace \"{}\"", ns.name);
    if !passphrase_only && try_touchid(ns, &reason) {
        return Ok(());
    }
    let passphrase = read_secret(&format!("passphrase for {}: ", ns.name))?;
    unlock_with(ns, passphrase)
}

pub fn lock(ns: &Ns) -> Result<()> {
    if let Some(mut s) = connect(ns, false)? {
        request(&mut s, &Request::Lock)?;
    }
    Ok(())
}

pub fn status(ns: &Ns) -> Result<()> {
    print!("{}: ", ns.name);
    let Some(mut s) = connect(ns, false)? else {
        println!("locked (daemon not running)");
        return Ok(());
    };
    match request(&mut s, &Request::Status)? {
        Response::Status {
            unlocked: false, ..
        } => println!("locked"),
        Response::Status {
            leases,
            absolute_left_secs,
            ..
        } => println!(
            "unlocked ({leases} active, hard lock in {}m)",
            absolute_left_secs / 60
        ),
        _ => return Err("unexpected response".into()),
    }
    Ok(())
}

fn exec_request(ns: &Ns, profile: &str) -> Result<(UnixStream, Response)> {
    let mut s = connect(ns, true)?.ok_or("daemon unavailable")?;
    let profile = profile.into();
    let project = ns.project.as_ref().map(|p| p.display().to_string());
    let resp = request(&mut s, &Request::Exec { profile, project })?;
    Ok((s, resp))
}

/// 잠겨 있으면 GUI로 패스프레이즈를 묻는다(최대 3번). 저장소의 .sagebox가 다른 네임스페이스를
/// 요청할 수 있으므로, 사용자가 판단하도록 네임스페이스·프로젝트 경로·요청한 부모 프로세스를 보여 준다.
fn gui_unlock(ns: &Ns, profile: &str) -> Result<()> {
    let parent = Command::new("ps")
        .args([
            "-o",
            "comm=",
            "-p",
            &std::os::unix::process::parent_id().to_string(),
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let project = std::env::current_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    let what = format!(
        "namespace \"{}\" to run profile \"{profile}\"\nproject: {project}\nrequested by: {parent}",
        ns.name
    );
    if try_touchid(ns, &format!("unlock sagebox {what}")) {
        return Ok(());
    }
    let mut message = format!("Unlock sagebox {what}");
    let mut last = None;
    for _ in 0..3 {
        let passphrase = prompt::ask(&message)
            .map_err(|e| format!("locked: run `{}` ({e})", unlock_hint(ns)))?;
        match unlock_with(ns, passphrase) {
            Ok(()) => return Ok(()),
            Err(e) => {
                message = format!("Wrong passphrase. Unlock sagebox {what}");
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| "unlock failed".into()))
}

/// 성공하면 반환하지 않는다. 이 프로세스가 프로필 명령으로 바뀌고, 임대 소켓을 물려받은
/// 그 프로세스(와 자식들)가 모두 끝나면 데몬이 임대 종료를 감지한다.
pub fn exec(ns: &Ns, profile: &str) -> Result<()> {
    let (mut s, mut resp) = exec_request(ns, profile)?;
    if matches!(resp, Response::Locked) {
        crate::debug::log(format_args!(
            "namespace {} is locked; asking via GUI",
            ns.name
        ));
        gui_unlock(ns, profile)?;
        (s, resp) = exec_request(ns, profile)?;
    }
    let Response::Exec { command, env } = resp else {
        return Err(format!("locked: run `{}`", unlock_hint(ns)).into());
    };
    // Rust는 소켓을 CLOEXEC로 만든다. 임대 소켓만 풀어 execve 뒤에도 열려 있게 한다.
    if unsafe { libc::fcntl(s.as_raw_fd(), libc::F_SETFD, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let _lease = s.into_raw_fd();
    let err = Command::new(&command[0])
        .args(&command[1..])
        .envs(env.iter().map(|(k, v)| (k, v.as_str())))
        .exec();
    Err(format!("exec {}: {err}", command[0]).into())
}
