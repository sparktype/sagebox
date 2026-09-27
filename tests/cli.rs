// 임시 SECRETBOX_HOME에서 관리 CLI 흐름(init → set → profile → list/rm)을 실행해 보는 통합 테스트
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn sbx(home: &Path, stdin: &str, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secretbox"))
        .args(args)
        .env("SECRETBOX_HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn admin_flow() {
    let home = std::env::temp_dir().join(format!("sbx-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let abs = if cfg!(windows) {
        "C:\\bin\\tool.exe"
    } else {
        "/usr/bin/env"
    };

    assert!(sbx(&home, "pw\npw\n", &["init"]).status.success());
    assert!(
        !sbx(&home, "pw\npw\n", &["init"]).status.success(),
        "re-init must fail"
    );
    assert!(sbx(&home, "pw\nghp_123\n", &["set", "gh"]).status.success());

    let raw = std::fs::read(home.join("vault")).unwrap();
    assert!(
        !raw.windows(7).any(|w| w == b"ghp_123"),
        "plaintext on disk"
    );

    let o = sbx(&home, "pw\n", &["profile", "add", "p", "--", "env"]);
    assert!(stderr(&o).contains("absolute path"));
    let o = sbx(
        &home,
        "pw\n",
        &["profile", "add", "p", "--env", "X=nope", "--", abs],
    );
    assert!(stderr(&o).contains("no secret named nope"));
    let o = sbx(
        &home,
        "pw\n",
        &[
            "profile",
            "add",
            "github",
            "--env",
            "GITHUB_TOKEN=gh",
            "--",
            abs,
        ],
    );
    assert!(o.status.success(), "{}", stderr(&o));

    let o = sbx(&home, "pw\n", &["rm", "gh"]);
    assert!(stderr(&o).contains("used by profiles: github"));
    assert!(stderr(&sbx(&home, "wrong\n", &["list"])).contains("wrong passphrase"));

    let o = sbx(&home, "pw\n", &["list"]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("gh") && out.contains("github: [GITHUB_TOKEN=gh]"));
    assert!(!out.contains("ghp_123"), "list must not print values");

    assert!(
        sbx(&home, "pw\n", &["profile", "rm", "github"])
            .status
            .success()
    );
    assert!(sbx(&home, "pw\n", &["rm", "gh"]).status.success());

    std::fs::remove_dir_all(&home).unwrap();
}

/// 테스트가 실패해도 데몬 프로세스를 정리한다.
#[cfg(unix)]
struct Daemon(std::process::Child);

#[cfg(unix)]
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
#[test]
fn daemon_session_and_exec() {
    use std::os::unix::fs::PermissionsExt;

    let home = std::env::temp_dir().join(format!("sbx-d-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let ok = |o: Output| assert!(o.status.success(), "{}", stderr(&o));
    ok(sbx(&home, "pw\npw\n", &["init"]));
    ok(sbx(&home, "pw\nghp_123\n", &["set", "gh"]));
    ok(sbx(
        &home,
        "pw\n",
        &[
            "profile",
            "add",
            "github",
            "--env",
            "GITHUB_TOKEN=gh",
            "--",
            "/usr/bin/env",
        ],
    ));
    assert!(stderr(&sbx(&home, "", &["exec", "github"])).contains("cannot reach daemon"));

    let _d = Daemon(
        Command::new(env!("CARGO_BIN_EXE_secretbox"))
            .arg("daemon")
            .env("SECRETBOX_HOME", &home)
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let sock = home.join("sock");
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(stderr(&sbx(&home, "", &["daemon"])).contains("already running"));

    let stdout = |o: &Output| String::from_utf8_lossy(&o.stdout).into_owned();
    assert_eq!(stdout(&sbx(&home, "", &["status"])), "locked\n");
    assert!(stderr(&sbx(&home, "", &["exec", "github"])).contains("locked"));
    assert!(stderr(&sbx(&home, "wrong\n", &["unlock"])).contains("wrong passphrase"));

    ok(sbx(&home, "pw\n", &["unlock"]));
    assert!(stdout(&sbx(&home, "", &["status"])).starts_with("unlocked"));
    let o = sbx(&home, "", &["exec", "github"]);
    assert!(
        stdout(&o).contains("GITHUB_TOKEN=ghp_123"),
        "{}",
        stderr(&o)
    );
    assert!(stderr(&sbx(&home, "", &["exec", "nope"])).contains("no profile named nope"));

    ok(sbx(&home, "", &["lock"]));
    assert!(stderr(&sbx(&home, "", &["exec", "github"])).contains("locked"));

    let audit = std::fs::read_to_string(home.join("audit.log")).unwrap();
    assert!(!audit.contains("ghp_123"), "secret value in audit log");
    assert!(
        audit.contains(r#""profile":"github","result":"ok: gh""#),
        "{audit}"
    );
    assert!(audit.contains("denied: wrong passphrase"));
    assert_eq!(audit.lines().count(), 7, "{audit}");
    let mode = std::fs::metadata(home.join("audit.log"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
        0o600
    );

    drop(_d);
    std::fs::remove_dir_all(&home).unwrap();
}
