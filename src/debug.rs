// SAGEBOX_DEBUG=1일 때만 판단 과정을 남기는 디버그 로그. 호출하는 쪽은 비밀 값·패스프레이즈를 넘기지 않는다.
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

static FILE: OnceLock<Mutex<File>> = OnceLock::new();

/// 환경변수가 비어 있지 않고 "0"이 아니면 켜진다. 자동 기동된 데몬은 띄운 쪽의 환경을 물려받는다.
pub fn flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty() && v != "0")
}

pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| flag("SAGEBOX_DEBUG"))
}

/// 데몬은 stderr가 /dev/null이라 파일(0600)로 남긴다. 설정하지 않으면 stderr로 쓴다.
pub fn to_file(path: &Path) {
    if !enabled() {
        return;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    if let Ok(f) = opts.open(path) {
        let _ = FILE.set(Mutex::new(f));
    }
}

pub fn log(msg: std::fmt::Arguments) {
    if !enabled() {
        return;
    }
    let line = format!(
        "{} [{}] {msg}",
        crate::vault::unix_now(),
        std::process::id()
    );
    match FILE.get() {
        Some(f) => {
            let _ = writeln!(f.lock().unwrap(), "{line}");
        }
        None => eprintln!("sgb debug: {line}"),
    }
}
