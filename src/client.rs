// 데몬에 unlock/lock/status/exec를 요청하고, exec는 받은 환경변수로 프로필 명령을 execve하는 클라이언트
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use crate::admin::read_secret;
use crate::daemon::{Request, Response, recv, send};
use crate::vault::Result;

fn request(dir: &Path, req: &Request) -> Result<Response> {
    let mut s = UnixStream::connect(dir.join("sock"))
        .map_err(|e| format!("cannot reach daemon ({e}); start it with `secretbox daemon`"))?;
    send(&mut s, req)?;
    s.shutdown(Shutdown::Write)?;
    match recv(&mut s)? {
        Response::Error { message } => Err(message.into()),
        resp => Ok(resp),
    }
}

pub fn unlock(dir: &Path) -> Result<()> {
    let passphrase = read_secret("passphrase: ")?;
    request(dir, &Request::Unlock { passphrase })?;
    Ok(())
}

pub fn lock(dir: &Path) -> Result<()> {
    request(dir, &Request::Lock)?;
    Ok(())
}

pub fn status(dir: &Path) -> Result<()> {
    match request(dir, &Request::Status)? {
        Response::Status {
            unlocked: false, ..
        } => println!("locked"),
        Response::Status {
            idle_left_secs,
            absolute_left_secs,
            ..
        } => println!(
            "unlocked (idle lock in {}m, hard lock in {}m)",
            idle_left_secs / 60,
            absolute_left_secs / 60
        ),
        _ => return Err("unexpected response".into()),
    }
    Ok(())
}

/// 성공하면 반환하지 않는다. 이 프로세스가 프로필 명령으로 바뀐다.
pub fn exec(dir: &Path, profile: &str) -> Result<()> {
    let Response::Exec { command, env } = request(
        dir,
        &Request::Exec {
            profile: profile.into(),
        },
    )?
    else {
        return Err("unexpected response".into());
    };
    let err = Command::new(&command[0])
        .args(&command[1..])
        .envs(env.iter().map(|(k, v)| (k, v.as_str())))
        .exec();
    Err(format!("exec {}: {err}", command[0]).into())
}
