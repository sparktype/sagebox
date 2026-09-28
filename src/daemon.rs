// 세션 키(DEK)를 보관하고, exec로 띄운 MCP 서버들의 임대가 모두 끝나면 스스로 종료하는 데몬
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::audit::{self, AuditLog};
use crate::vault::{self, Dek, Header, Result};

/// 임대가 계속 남아 있어도(종료하지 않는 MCP 서버 등) 이 시간이 지나면 잠근다.
const ABSOLUTE_TTL: Duration = Duration::from_secs(8 * 60 * 60);
/// 마지막 임대가 끝난 뒤 기다리는 시간. MCP 서버·에이전트 재시작을 흡수한다.
const LEASE_GRACE: Duration = Duration::from_secs(30);
/// 터미널에서 unlock한 뒤 첫 임대(에이전트 실행)까지 기다리는 시간.
const FIRST_LEASE_WAIT: Duration = Duration::from_secs(10 * 60);
/// 잠긴 채 요청이 없으면 종료. GUI 프롬프트에 입력하는 동안은 살아 있어야 한다.
const LOCKED_IDLE: Duration = Duration::from_secs(2 * 60);
const CHECK_EVERY: Duration = Duration::from_secs(5);
/// 벽시계가 단조 시계보다 이만큼 더 흘렀으면 잠자기로 본다(NTP 보정 정도의 오차는 넘지 않는다).
const SLEEP_GAP: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MSG: usize = 1 << 20;

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Unlock {
        passphrase: Zeroizing<String>,
    },
    /// 클라이언트가 Secure Enclave 슬롯으로 푼 DEK. 데몬은 볼트를 열어 검증한 뒤 세션을 시작한다.
    UnlockKey {
        dek: Dek,
    },
    Lock,
    Status,
    Exec {
        profile: String,
        /// .sagebox로 네임스페이스가 정해졌을 때의 프로젝트 디렉터리
        #[serde(default)]
        project: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Error {
        message: String,
    },
    Locked,
    Status {
        unlocked: bool,
        leases: usize,
        absolute_left_secs: u64,
    },
    Exec {
        command: Vec<String>,
        env: BTreeMap<String, Zeroizing<String>>,
    },
}

/// 길이(u32 LE) + JSON. exec 연결은 임대로 열어 두므로 EOF로 메시지 끝을 알릴 수 없다.
/// 버퍼를 미리 잡아 재할당으로 평문 사본이 남지 않게 한다.
pub fn send<T: Serialize>(s: &mut UnixStream, msg: &T) -> Result<()> {
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_MSG));
    buf.extend_from_slice(&[0; 4]);
    serde_json::to_writer(&mut *buf, msg)?;
    let len = u32::try_from(buf.len() - 4)?;
    buf[..4].copy_from_slice(&len.to_le_bytes());
    s.write_all(&buf)?;
    Ok(())
}

pub fn recv<T: DeserializeOwned>(s: &mut UnixStream) -> Result<T> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MSG {
        return Err("message too large".into());
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    s.read_exact(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}

struct Session {
    dek: Dek,
    unlocked_at: SystemTime,
}

struct State {
    session: Option<Session>,
    /// 살아 있는 exec 임대 수 (= sagebox로 띄운 MCP 서버 수)
    leases: usize,
    /// 임대가 0이 된 시각. 잠긴 동안에는 마지막 요청 시각.
    idle_since: SystemTime,
    had_lease: bool,
}

/// 두 확인 사이에 시스템이 잠들었는가. 벽시계는 잠자기 중에도 흐르지만 Instant(macOS
/// CLOCK_UPTIME_RAW, Linux CLOCK_MONOTONIC)는 멈추므로, 벽시계만 크게 앞서 있으면 잠들었던 것이다.
/// 벽시계 간격만 보면 스케줄링 지연(바쁜 시스템)과 구분할 수 없다.
fn slept(wall_delta: Duration, mono_delta: Duration) -> bool {
    wall_delta.saturating_sub(mono_delta) > SLEEP_GAP
}

/// 데몬이 DEK를 지우고 종료해야 하는가. 시간은 벽시계로 잰다(단조 시계는 절전 중 멈춘다).
/// 시계가 뒤로 가면 종료한다.
fn should_exit(st: &State, now: SystemTime) -> bool {
    let since = |t: SystemTime| now.duration_since(t).unwrap_or(Duration::MAX);
    let idle = st.leases == 0
        && since(st.idle_since)
            >= match (&st.session, st.had_lease) {
                (None, _) => LOCKED_IDLE,
                (Some(_), true) => LEASE_GRACE,
                (Some(_), false) => FIRST_LEASE_WAIT,
            };
    idle || st
        .session
        .as_ref()
        .is_some_and(|s| since(s.unlocked_at) >= ABSOLUTE_TTL)
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

/// 응답을 보낸 뒤 연결을 어떻게 할지.
enum Next {
    Close,
    /// 연결을 열어 둔 채 EOF(= MCP 서버 종료)를 기다린다.
    Lease(i32),
    /// lock: 응답 후 DEK를 지우고 종료한다.
    Exit,
}

struct Daemon {
    vault: PathBuf,
    sock: PathBuf,
    audit_log: Mutex<AuditLog>,
    state: Mutex<State>,
}

pub fn serve(dir: &Path) -> Result<()> {
    let sock = dir.join("sock");
    if UnixStream::connect(&sock).is_ok() {
        return Err("daemon already running".into());
    }
    // ponytail: 두 클라이언트가 동시에 데몬을 띄우면 늦게 bind한 쪽이 소켓을 가져가고,
    // 먼저 뜬 쪽은 요청을 못 받은 채 LOCKED_IDLE 뒤 종료한다. 문제되면 flock으로 직렬화
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    crate::debug::to_file(&dir.join("debug.log"));
    // 개발·디버깅용: 화면을 잠근 채 에이전트를 돌릴 때 등
    let autolock = !crate::debug::flag("SAGEBOX_NO_AUTOLOCK");
    crate::debug::log(format_args!(
        "daemon started on {} autolock={autolock}",
        sock.display()
    ));

    let d = Arc::new(Daemon {
        vault: dir.join("vault"),
        sock,
        audit_log: Mutex::new(AuditLog::new(dir.join("audit.log"))),
        state: Mutex::new(State {
            session: None,
            leases: 0,
            idle_since: SystemTime::now(),
            had_lease: false,
        }),
    });
    let checker = d.clone();
    std::thread::spawn(move || {
        let (mut wall, mut mono) = (SystemTime::now(), Instant::now());
        loop {
            std::thread::sleep(CHECK_EVERY);
            let (now_wall, now_mono) = (SystemTime::now(), Instant::now());
            let wall_delta = now_wall.duration_since(wall).unwrap_or_default();
            if autolock && slept(wall_delta, now_mono - mono) {
                checker.shutdown("system sleep");
            }
            #[cfg(target_os = "macos")]
            if autolock && crate::macos::screen_locked() == Some(true) {
                checker.shutdown("screen locked");
            }
            if should_exit(&checker.state.lock().unwrap(), now_wall) {
                checker.shutdown("expired");
            }
            (wall, mono) = (now_wall, now_mono);
        }
    });

    for conn in listener.incoming() {
        let Ok(s) = conn else { continue };
        let d = d.clone();
        std::thread::spawn(move || d.serve_conn(s));
    }
    Ok(())
}

impl Daemon {
    fn serve_conn(&self, mut s: UnixStream) {
        let _ = s.set_read_timeout(Some(IO_TIMEOUT));
        let _ = s.set_write_timeout(Some(IO_TIMEOUT));
        let (resp, next) = self.handle(&mut s).unwrap_or_else(|e| {
            let message = e.to_string();
            (Response::Error { message }, Next::Close)
        });
        let sent = send(&mut s, &resp);
        drop(resp); // env의 비밀 값을 바로 지운다.
        match next {
            Next::Close => {}
            Next::Exit => self.shutdown("lock"),
            Next::Lease(pid) => {
                if sent.is_ok() {
                    let _ = s.set_read_timeout(None);
                    // EOF(0) 또는 오류 = 이 소켓을 가진 프로세스가 모두 사라졌다.
                    let mut buf = [0u8; 64];
                    while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
                }
                self.release(pid);
            }
        }
    }

    fn handle(&self, s: &mut UnixStream) -> Result<(Response, Next)> {
        let (uid, pid) = peer(s)?;
        if uid != unsafe { libc::geteuid() } {
            self.audit(pid, "connect", None, &format!("denied: uid {uid}"))?;
            return Err("permission denied".into());
        }
        let req: Request = recv(s)?;
        let mut st = self.state.lock().unwrap();
        let now = SystemTime::now();
        if st.session.is_none() {
            st.idle_since = now;
        }
        match req {
            Request::Status => Ok((status(&st, now), Next::Close)),
            Request::Lock => {
                self.audit(pid, "lock", None, "ok")?;
                Ok((Response::Ok, Next::Exit))
            }
            Request::Unlock { passphrase } => {
                let result = self.unlock(passphrase.as_bytes());
                self.begin(pid, &mut st, now, result, "passphrase")
            }
            Request::UnlockKey { dek } => {
                let result = self.check_dek(dek);
                self.begin(pid, &mut st, now, result, "secure_enclave")
            }
            Request::Exec { profile, project } => {
                let Some(sess) = &st.session else {
                    self.audit(pid, "exec", Some(&profile), "denied: locked")?;
                    return Ok((Response::Locked, Next::Close));
                };
                let result = self.exec(&sess.dek, &profile, project.as_deref());
                let outcome = match &result {
                    Ok((_, names)) => format!("ok: {}", names.join(",")),
                    Err(e) => format!("denied: {e}"),
                };
                // 기록을 남기지 못하면 비밀을 내보내지 않는다.
                self.audit(pid, "exec", Some(&profile), &outcome)?;
                let (resp, _) = result?;
                st.leases += 1;
                st.had_lease = true;
                Ok((resp, Next::Lease(pid)))
            }
        }
    }

    fn release(&self, pid: i32) {
        let mut st = self.state.lock().unwrap();
        st.leases -= 1;
        if st.leases == 0 {
            st.idle_since = SystemTime::now();
        }
        let _ = self.audit(pid, "release", None, &format!("{} active", st.leases));
    }

    /// DEK를 지우고 소켓을 치운 뒤 프로세스를 끝낸다.
    fn shutdown(&self, reason: &str) -> ! {
        let mut st = self.state.lock().unwrap();
        st.session = None; // Dek는 drop될 때 0으로 지워진다.
        let _ = self.audit(std::process::id() as i32, "end", None, reason);
        let _ = std::fs::remove_file(&self.sock);
        std::process::exit(0)
    }

    /// 잠금 해제 결과로 세션을 시작한다. via는 감사 로그용 해제 수단이다.
    fn begin(
        &self,
        pid: i32,
        st: &mut State,
        now: SystemTime,
        result: Result<Dek>,
        via: &str,
    ) -> Result<(Response, Next)> {
        if let Ok(dek) = &result {
            // 감사 키는 데몬(= 세션)이 끝날 때까지 유지된다.
            self.audit_log
                .lock()
                .unwrap()
                .set_key(audit::derive_key(dek)?)?;
        }
        let outcome = match &result {
            Ok(_) => format!("ok ({via})"),
            Err(e) => format!("denied ({via}): {e}"),
        };
        self.audit(pid, "unlock", None, &outcome)?;
        st.session = Some(Session {
            dek: result?,
            unlocked_at: now,
        });
        st.idle_since = now;
        Ok((Response::Ok, Next::Close))
    }

    fn check_dek(&self, dek: Dek) -> Result<Dek> {
        vault::open(&std::fs::read(&self.vault)?, &dek)
            .map_err(|_| "key does not open this vault")?;
        Ok(dek)
    }

    fn unlock(&self, passphrase: &[u8]) -> Result<Dek> {
        let file = std::fs::read(&self.vault)?;
        let (header, _) = Header::parse(&file)?;
        let dek = header.unlock_passphrase(passphrase)?;
        vault::open(&file, &dek)?;
        Ok(dek)
    }

    /// 프로필의 명령과 환경변수, 그리고 감사 로그용 비밀 이름 목록.
    fn exec(
        &self,
        dek: &Dek,
        profile: &str,
        project: Option<&str>,
    ) -> Result<(Response, Vec<String>)> {
        let (_, v) = vault::open(&std::fs::read(&self.vault)?, dek)?;
        v.check_project(project)?;
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
        crate::debug::log(format_args!(
            "{op} pid={pid} profile={profile:?} -> {result}"
        ));
        let line = serde_json::json!({"ts": vault::unix_now(), "pid": pid, "op": op, "profile": profile, "result": result});
        self.audit_log.lock().unwrap().append(line)
    }
}

fn status(st: &State, now: SystemTime) -> Response {
    let absolute_left_secs = st.session.as_ref().map_or(0, |s| {
        ABSOLUTE_TTL
            .saturating_sub(now.duration_since(s.unlocked_at).unwrap_or(ABSOLUTE_TTL))
            .as_secs()
    });
    Response::Status {
        unlocked: st.session.is_some(),
        leases: st.leases,
        absolute_left_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    const SEC: Duration = Duration::from_secs(1);
    const MIN: Duration = Duration::from_secs(60);

    fn state(unlocked: bool, leases: usize, had_lease: bool, t0: SystemTime) -> State {
        State {
            session: unlocked.then(|| Session {
                dek: Zeroizing::new([0; 32]),
                unlocked_at: t0,
            }),
            leases,
            idle_since: t0,
            had_lease,
        }
    }

    #[test]
    fn exit_policy() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000_000);
        // 잠긴 데몬: 요청 없이 2분이면 종료
        assert!(!should_exit(&state(false, 0, false, t0), t0 + MIN));
        assert!(should_exit(&state(false, 0, false, t0), t0 + 2 * MIN));
        // 터미널 unlock 후 첫 임대 전: 10분까지 기다림
        assert!(!should_exit(&state(true, 0, false, t0), t0 + 9 * MIN));
        assert!(should_exit(&state(true, 0, false, t0), t0 + 10 * MIN));
        // 임대가 있으면 유지, 마지막 임대가 끝나면 30초 유예
        assert!(!should_exit(&state(true, 2, true, t0), t0 + 60 * MIN));
        assert!(!should_exit(&state(true, 0, true, t0), t0 + 29 * SEC));
        assert!(should_exit(&state(true, 0, true, t0), t0 + 30 * SEC));
        // 임대가 남아 있어도 8시간이면 종료
        assert!(should_exit(&state(true, 1, true, t0), t0 + 8 * 60 * MIN));
        // 시계가 뒤로 가면 종료
        assert!(should_exit(&state(true, 1, true, t0), t0 - MIN));
    }

    #[test]
    fn sleep_detection() {
        // 정상: 두 시계가 함께 5초 흐름
        assert!(!slept(5 * SEC, 5 * SEC));
        // 바쁜 시스템: 확인이 늦어져도 두 시계가 함께 흐르면 잠자기가 아니다
        assert!(!slept(90 * SEC, 90 * SEC));
        // 잠자기: 벽시계만 10분 흐르고 단조 시계는 5초
        assert!(slept(10 * MIN, 5 * SEC));
        // NTP 보정 정도의 차이는 무시
        assert!(!slept(15 * SEC, 5 * SEC));
    }
}
