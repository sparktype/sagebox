// 세션 키(DEK)를 보관하고 Unix 소켓으로 unlock/lock/status/exec 요청을 처리하는 데몬
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::audit::{self, AuditLog};
use crate::vault::{self, Dek, Header, Result};

const IDLE_TTL: Duration = Duration::from_secs(30 * 60);
const ABSOLUTE_TTL: Duration = Duration::from_secs(8 * 60 * 60);
const EXPIRY_CHECK: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MSG: usize = 1 << 20;

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Unlock { passphrase: Zeroizing<String> },
    Lock,
    Status,
    Exec { profile: String },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Error {
        message: String,
    },
    Status {
        unlocked: bool,
        idle_left_secs: u64,
        absolute_left_secs: u64,
    },
    Exec {
        command: Vec<String>,
        env: BTreeMap<String, Zeroizing<String>>,
    },
}

/// 한 연결에 메시지 하나. 버퍼를 미리 잡아 재할당으로 평문 사본이 남지 않게 한다.
pub fn send<T: Serialize>(s: &mut UnixStream, msg: &T) -> Result<()> {
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_MSG));
    serde_json::to_writer(&mut *buf, msg)?;
    s.write_all(&buf)?;
    Ok(())
}

pub fn recv<T: DeserializeOwned>(s: &mut UnixStream) -> Result<T> {
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_MSG));
    s.take(MAX_MSG as u64).read_to_end(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}

struct Session {
    dek: Dek,
    unlocked_at: SystemTime,
    last_used: SystemTime,
}

/// 유휴 30분 또는 잠금 해제 후 8시간 중 하나라도 넘으면 만료.
/// 벽시계를 쓰는 이유는 단조 시계(Instant)가 절전 중에 멈추기 때문이다. 시계가 뒤로 가면 잠근다.
fn session_expired(unlocked_at: SystemTime, last_used: SystemTime, now: SystemTime) -> bool {
    match (
        now.duration_since(unlocked_at),
        now.duration_since(last_used),
    ) {
        (Ok(total), Ok(idle)) => total >= ABSOLUTE_TTL || idle >= IDLE_TTL,
        _ => true,
    }
}

fn expire(session: &mut Option<Session>) {
    if let Some(s) = session
        && session_expired(s.unlocked_at, s.last_used, SystemTime::now())
    {
        *session = None; // Dek는 drop될 때 0으로 지워진다.
    }
}

/// 연결한 프로세스의 (uid, pid).
fn peer(s: &UnixStream) -> Result<(u32, i32)> {
    let fd = s.as_raw_fd();
    #[cfg(target_os = "linux")]
    unsafe {
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        ) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((cred.uid, cred.pid))
    }
    #[cfg(target_os = "macos")]
    unsafe {
        let (mut uid, mut gid, mut pid) = (0, 0, 0 as libc::pid_t);
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        if libc::getpeereid(fd, &mut uid, &mut gid) != 0
            || libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&raw mut pid).cast(),
                &mut len,
            ) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((uid, pid))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        Err("peer credentials not supported on this platform".into())
    }
}

struct Daemon {
    vault: PathBuf,
    audit_log: Mutex<AuditLog>,
    session: Arc<Mutex<Option<Session>>>,
}

pub fn serve(dir: &Path) -> Result<()> {
    let sock = dir.join("sock");
    if UnixStream::connect(&sock).is_ok() {
        return Err("daemon already running".into());
    }
    let _ = std::fs::remove_file(&sock); // 이전 실행이 남긴 소켓
    let listener = UnixListener::bind(&sock)?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;

    let d = Daemon {
        vault: dir.join("vault"),
        audit_log: Mutex::new(AuditLog::new(dir.join("audit.log"))),
        session: Arc::new(Mutex::new(None)),
    };
    let session = d.session.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(EXPIRY_CHECK);
            expire(&mut session.lock().unwrap());
        }
    });

    eprintln!("secretbox daemon listening on {}", sock.display());
    // ponytail: 요청을 한 번에 하나씩 처리한다. unlock의 KDF(수백 ms) 동안 다른 요청은 기다린다
    for conn in listener.incoming() {
        let Ok(mut s) = conn else { continue };
        let _ = s.set_read_timeout(Some(IO_TIMEOUT));
        let _ = s.set_write_timeout(Some(IO_TIMEOUT));
        let resp = d.handle(&mut s).unwrap_or_else(|e| Response::Error {
            message: e.to_string(),
        });
        let _ = send(&mut s, &resp);
    }
    Ok(())
}

impl Daemon {
    fn handle(&self, s: &mut UnixStream) -> Result<Response> {
        let (uid, pid) = peer(s)?;
        if uid != unsafe { libc::geteuid() } {
            self.audit(pid, "connect", None, &format!("denied: uid {uid}"))?;
            return Err("permission denied".into());
        }
        let req: Request = recv(s)?;
        let mut session = self.session.lock().unwrap();
        expire(&mut session);
        match req {
            Request::Status => Ok(status(&session)),
            Request::Lock => {
                *session = None;
                self.audit(pid, "lock", None, "ok")?;
                Ok(Response::Ok)
            }
            Request::Unlock { passphrase } => {
                let result = self.unlock(passphrase.as_bytes());
                if let Ok(dek) = &result {
                    // 첫 unlock부터 감사 로그에 MAC 체인을 건다. 키는 lock 뒤에도 유지된다.
                    self.audit_log
                        .lock()
                        .unwrap()
                        .set_key(audit::derive_key(dek)?)?;
                }
                let outcome = match &result {
                    Ok(_) => "ok".to_string(),
                    Err(e) => format!("denied: {e}"),
                };
                self.audit(pid, "unlock", None, &outcome)?;
                let now = SystemTime::now();
                *session = Some(Session {
                    dek: result?,
                    unlocked_at: now,
                    last_used: now,
                });
                Ok(Response::Ok)
            }
            Request::Exec { profile } => {
                let result = match session.as_mut() {
                    None => Err("locked (run `secretbox unlock`)".into()),
                    Some(sess) => self.exec(&sess.dek, &profile),
                };
                let outcome = match &result {
                    Ok((_, names)) => format!("ok: {}", names.join(",")),
                    Err(e) => format!("denied: {e}"),
                };
                // 기록을 남기지 못하면 비밀을 내보내지 않는다.
                self.audit(pid, "exec", Some(&profile), &outcome)?;
                let (resp, _) = result?;
                if let Some(sess) = session.as_mut() {
                    sess.last_used = SystemTime::now();
                }
                Ok(resp)
            }
        }
    }

    fn unlock(&self, passphrase: &[u8]) -> Result<Dek> {
        let file = std::fs::read(&self.vault)?;
        let (header, _) = Header::parse(&file)?;
        let dek = header.unlock_passphrase(passphrase)?;
        vault::open(&file, &dek)?;
        Ok(dek)
    }

    /// 프로필의 명령과 환경변수, 그리고 감사 로그용 비밀 이름 목록.
    fn exec(&self, dek: &Dek, profile: &str) -> Result<(Response, Vec<String>)> {
        let (_, v) = vault::open(&std::fs::read(&self.vault)?, dek)?;
        let p = v
            .profiles
            .get(profile)
            .ok_or(format!("no profile named {profile}"))?;
        v.check_expiry(p.env.values(), vault::unix_now())?;
        let mut env = BTreeMap::new();
        for (var, name) in &p.env {
            let value = v.secrets.get(name).ok_or(format!(
                "profile {profile} references missing secret {name}"
            ))?;
            env.insert(var.clone(), value.clone());
        }
        let names = p.env.values().cloned().collect();
        let resp = Response::Exec {
            command: p.command.clone(),
            env,
        };
        Ok((resp, names))
    }

    /// 비밀 값은 절대 넣지 않는다.
    fn audit(&self, pid: i32, op: &str, profile: Option<&str>, result: &str) -> Result<()> {
        let line = serde_json::json!({"ts": vault::unix_now(), "pid": pid, "op": op, "profile": profile, "result": result});
        self.audit_log.lock().unwrap().append(line)
    }
}

fn status(session: &Option<Session>) -> Response {
    let now = SystemTime::now();
    let left = |since: SystemTime, ttl: Duration| {
        ttl.saturating_sub(now.duration_since(since).unwrap_or(ttl))
            .as_secs()
    };
    match session {
        None => Response::Status {
            unlocked: false,
            idle_left_secs: 0,
            absolute_left_secs: 0,
        },
        Some(s) => Response::Status {
            unlocked: true,
            idle_left_secs: left(s.last_used, IDLE_TTL),
            absolute_left_secs: left(s.unlocked_at, ABSOLUTE_TTL),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn expiry_policy() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000_000);
        // 방금 풀고 방금 씀
        assert!(!session_expired(t0, t0, t0));
        // 유휴 29분은 유지, 30분은 만료
        assert!(!session_expired(t0, t0, t0 + 29 * MIN));
        assert!(session_expired(t0, t0, t0 + 30 * MIN));
        // 계속 사용해도 8시간이 되면 만료
        let busy = t0 + 8 * 60 * MIN - MIN;
        assert!(!session_expired(t0, busy, busy));
        assert!(session_expired(t0, busy, busy + MIN));
        // 시계가 뒤로 가면 만료
        assert!(session_expired(t0, t0, t0 - MIN));
    }
}
