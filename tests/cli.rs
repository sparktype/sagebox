// 임시 SECRETBOX_HOME에서 관리 CLI 흐름(init → set → profile → list/rm)을 실행해 보는 통합 테스트
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn sbx(home: &Path, stdin: &str, args: &[&str]) -> Output {
    sbx_in(Path::new("."), home, stdin, args)
}

/// cwd에서 실행한다. 네임스페이스는 cwd 위의 .secretbox 파일로도 정해진다.
fn sbx_in(cwd: &Path, home: &Path, stdin: &str, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secretbox"))
        .args(args)
        .current_dir(cwd)
        .env("SECRETBOX_HOME", home)
        .env("SECRETBOX_NO_GUI", "1")
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

    assert!(stderr(&sbx(&home, "short\nshort\n", &["init"])).contains("at least 8"));
    assert!(
        sbx(&home, "password\npassword\n", &["init"])
            .status
            .success()
    );
    assert!(
        !sbx(&home, "password\npassword\n", &["init"])
            .status
            .success(),
        "re-init must fail"
    );
    assert!(
        sbx(&home, "password\nghp_123\n", &["set", "gh"])
            .status
            .success()
    );

    let raw = std::fs::read(home.join("vault")).unwrap();
    assert!(
        !raw.windows(7).any(|w| w == b"ghp_123"),
        "plaintext on disk"
    );

    let o = sbx(&home, "", &["set", "gh", "--expires", "2020-01-01"]);
    assert!(stderr(&o).contains("not in the future"));
    let o = sbx(
        &home,
        "password\nghp_123\n",
        &["set", "gh", "--expires", "2099-01-01"],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let o = sbx(&home, "password\na\0b\n", &["set", "nul"]);
    assert!(stderr(&o).contains("NUL"));
    let o = sbx(
        &home,
        "",
        &["profile", "add", "p", "--env", "PATH=gh", "--", abs],
    );
    assert!(stderr(&o).contains("reserved variable PATH"));
    let o = sbx(&home, "password\n", &["profile", "add", "p", "--", "env"]);
    assert!(stderr(&o).contains("absolute path"));
    let o = sbx(
        &home,
        "password\n",
        &["profile", "add", "p", "--env", "X=nope", "--", abs],
    );
    assert!(stderr(&o).contains("no secret named nope"));
    let o = sbx(
        &home,
        "password\n",
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

    let o = sbx(&home, "password\n", &["rm", "gh"]);
    assert!(stderr(&o).contains("used by profiles: github"));
    assert!(stderr(&sbx(&home, "wrong\n", &["list"])).contains("wrong passphrase"));

    let o = sbx(&home, "password\n", &["list"]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("gh  (expires 2099-01-01)") && out.contains("github: [GITHUB_TOKEN=gh]"));
    assert!(!out.contains("ghp_123"), "list must not print values");

    assert!(
        sbx(&home, "password\n", &["profile", "rm", "github"])
            .status
            .success()
    );
    assert!(sbx(&home, "password\n", &["rm", "gh"]).status.success());

    std::fs::remove_dir_all(&home).unwrap();
}

/// 테스트가 실패해도 자동 기동된 데몬을 lock으로 끝낸다. (데이터 홈, 네임스페이스)
#[cfg(unix)]
struct LockOnDrop(std::path::PathBuf, &'static str);

#[cfg(unix)]
impl Drop for LockOnDrop {
    fn drop(&mut self) {
        let _ = sbx(&self.0, "", &["--ns", self.1, "lock"]);
    }
}

#[cfg(unix)]
fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if cond() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
    false
}

#[cfg(unix)]
#[test]
fn daemon_session_and_exec() {
    use std::os::unix::fs::PermissionsExt;

    let home = std::env::temp_dir().join(format!("sbx-d-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let _cleanup = LockOnDrop(home.clone(), "default");
    let ok = |o: Output| assert!(o.status.success(), "{}", stderr(&o));
    let stdout = |o: &Output| String::from_utf8_lossy(&o.stdout).into_owned();
    let status = || stdout(&sbx(&home, "", &["status"]));
    ok(sbx(&home, "password\npassword\n", &["init"]));
    ok(sbx(&home, "password\nghp_123\n", &["set", "gh"]));
    for (name, cmd) in [
        ("github", &["/usr/bin/env"][..]),
        ("sleeper", &["/bin/sleep", "30"]),
    ] {
        let mut args = vec!["profile", "add", name, "--env", "GITHUB_TOKEN=gh", "--"];
        args.extend(cmd);
        ok(sbx(&home, "password\n", &args));
    }
    assert_eq!(status(), "default: locked (daemon not running)\n");

    // 첫 exec가 데몬을 띄우고, 잠겨 있으니 GUI를 시도하다(테스트에서는 꺼 둠) unlock을 안내한다.
    let o = sbx(&home, "", &["exec", "github"]);
    assert!(stderr(&o).contains("secretbox unlock"), "{}", stderr(&o));
    let sock = home.join("sock");
    assert!(sock.exists(), "daemon was not auto-started");
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(status(), "default: locked\n");
    assert!(stderr(&sbx(&home, "", &["daemon"])).contains("already running"));

    assert!(stderr(&sbx(&home, "wrong\n", &["unlock"])).contains("wrong passphrase"));
    ok(sbx(&home, "password\n", &["unlock"]));
    assert!(
        status().starts_with("default: unlocked (0 active"),
        "{}",
        status()
    );

    let o = sbx(&home, "", &["exec", "github"]);
    assert!(
        stdout(&o).contains("GITHUB_TOKEN=ghp_123"),
        "{}",
        stderr(&o)
    );
    assert!(stderr(&sbx(&home, "", &["exec", "nope"])).contains("no profile named nope"));

    // 오래 사는 MCP 서버 대역: 임대가 1이 됐다가 프로세스가 죽으면 0으로 돌아온다.
    let mut sleeper = Command::new(env!("CARGO_BIN_EXE_secretbox"))
        .args(["exec", "sleeper"])
        .env("SECRETBOX_HOME", &home)
        .env("SECRETBOX_NO_GUI", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_until(|| status().starts_with("default: unlocked (1 active")),
        "{}",
        status()
    );
    sleeper.kill().unwrap();
    sleeper.wait().unwrap();
    assert!(
        wait_until(|| status().starts_with("default: unlocked (0 active")),
        "{}",
        status()
    );

    // lock은 DEK를 지우고 데몬을 끝낸다.
    ok(sbx(&home, "", &["lock"]));
    assert!(
        wait_until(|| !sock.exists()),
        "daemon still running after lock"
    );
    assert_eq!(status(), "default: locked (daemon not running)\n");

    let audit = std::fs::read_to_string(home.join("audit.log")).unwrap();
    assert!(!audit.contains("ghp_123"), "secret value in audit log");
    assert!(
        audit.contains(r#""profile":"github","result":"ok: gh""#),
        "{audit}"
    );
    assert!(audit.contains("denied: wrong passphrase") && audit.contains(r#""op":"release""#));
    let mode = std::fs::metadata(home.join("audit.log"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    // 첫 unlock 전 2줄(exec locked, unlock 실패)은 MAC이 없다. 이후 unlock, exec×3, release×2,
    // lock, end의 8줄이 체인에 들어간다.
    let o = sbx(&home, "password\n", &["audit", "verify"]);
    assert!(
        stdout(&o).contains("8 verified, 2 unauthenticated"),
        "{}{}\n{audit}",
        stdout(&o),
        stderr(&o)
    );
    assert!(o.status.success());
    let log = home.join("audit.log");
    let tampered = std::fs::read_to_string(&log)
        .unwrap()
        .replace("ok: gh", "ok: xx");
    std::fs::write(&log, tampered).unwrap();
    let o = sbx(&home, "password\n", &["audit", "verify"]);
    assert!(!o.status.success() && stdout(&o).contains("MAC mismatch"));

    std::fs::remove_dir_all(&home).unwrap();
}

#[cfg(unix)]
#[test]
fn namespaces_are_isolated() {
    let base = std::env::temp_dir().join(format!("sbx-ns-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (home, project) = (base.join("home"), base.join("acme-repo/src"));
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(base.join("acme-repo/.secretbox"), "namespace = \"acme\"\n").unwrap();
    let _lock_default = LockOnDrop(home.clone(), "default");
    let ok = |o: Output| assert!(o.status.success(), "{}", stderr(&o));
    let stdout = |o: &Output| String::from_utf8_lossy(&o.stdout).into_owned();

    // default와 acme는 볼트·패스프레이즈가 따로다.
    ok(sbx(&home, "personal1\npersonal1\n", &["init"]));
    ok(sbx(&home, "personal1\npersonal_tok\n", &["set", "gh"]));
    ok(sbx_in(&project, &home, "acmepass1\nacmepass1\n", &["init"]));
    ok(sbx_in(
        &project,
        &home,
        "acmepass1\nacme_tok\n",
        &["set", "gh"],
    ));
    for cwd in [Path::new("."), project.as_path()] {
        let pass = if cwd == project {
            "acmepass1\n"
        } else {
            "personal1\n"
        };
        let args = [
            "profile",
            "add",
            "github",
            "--env",
            "GITHUB_TOKEN=gh",
            "--",
            "/usr/bin/env",
        ];
        ok(sbx_in(cwd, &home, pass, &args));
    }
    assert!(home.join("ns/acme/vault").is_file() && home.join("vault").is_file());

    let o = sbx_in(&project, &home, "", &["ns"]);
    assert!(stdout(&o).contains("namespace: acme (from ") && stdout(&o).contains(".secretbox)"));
    assert!(
        stdout(&o).contains("available: default, acme"),
        "{}",
        stdout(&o)
    );

    // acme만 푼다. 프로젝트 안의 exec는 acme 토큰을 받는다.
    let _lock_acme = LockOnDrop(home.clone(), "acme");
    assert!(
        stderr(&sbx_in(&project, &home, "personal1\n", &["unlock"])).contains("wrong passphrase")
    );
    ok(sbx_in(&project, &home, "acmepass1\n", &["unlock"]));

    // 풀려 있어도 신뢰 등록 전의 저장소 디렉터리는 거부된다.
    let o = sbx_in(&project, &home, "", &["exec", "github"]);
    assert!(stderr(&o).contains("is not trusted"), "{}", stderr(&o));
    // 명시 인자(--ns)는 사용자가 쓴 설정이므로 신뢰 검사 대상이 아니다.
    let o = sbx(&home, "", &["--ns", "acme", "exec", "github"]);
    assert!(
        stdout(&o).contains("GITHUB_TOKEN=acme_tok"),
        "{}",
        stderr(&o)
    );
    // 패스프레이즈 없이는(에이전트 스스로는) 신뢰 등록할 수 없다.
    assert!(!sbx_in(&project, &home, "", &["trust"]).status.success());
    let o = sbx_in(&project, &home, "acmepass1\n", &["trust"]);
    assert!(
        stdout(&o).contains("trusted ") && stdout(&o).contains("for namespace acme"),
        "{}",
        stderr(&o)
    );

    let o = sbx_in(&project, &home, "", &["exec", "github"]);
    assert!(
        stdout(&o).contains("GITHUB_TOKEN=acme_tok"),
        "{}",
        stderr(&o)
    );
    assert!(!stdout(&o).contains("personal_tok"));

    // default는 여전히 잠겨 있다. 프로젝트 안에서 --ns로 넘어가도 마찬가지다.
    let o = sbx(&home, "", &["exec", "github"]);
    assert!(
        stderr(&o).contains("locked: run `secretbox unlock`"),
        "{}",
        stderr(&o)
    );
    let o = sbx_in(&project, &home, "", &["--ns", "default", "exec", "github"]);
    assert!(stderr(&o).contains("locked"), "{}", stderr(&o));
    assert!(stdout(&sbx_in(&project, &home, "", &["status"])).starts_with("acme: unlocked"));

    // 저장소가 .secretbox를 다른 네임스페이스로 바꾸면 그쪽 신뢰 목록에는 없으므로 거부된다.
    ok(sbx(
        &home,
        "otherpass\notherpass\n",
        &["--ns", "other", "init"],
    ));
    ok(sbx(&home, "otherpass\n", &["--ns", "other", "unlock"]));
    let _lock_other = LockOnDrop(home.clone(), "other");
    std::fs::write(base.join("acme-repo/.secretbox"), "namespace = \"other\"\n").unwrap();
    let o = sbx_in(&project, &home, "", &["exec", "github"]);
    assert!(stderr(&o).contains("is not trusted"), "{}", stderr(&o));
    std::fs::write(base.join("acme-repo/.secretbox"), "namespace = \"acme\"\n").unwrap();

    // 경로 탈출과 잘못된 이름은 거부한다.
    assert!(stderr(&sbx(&home, "", &["--ns", "../x", "list"])).contains("invalid namespace"));

    // 감사 로그도 분리된다.
    let acme_log = std::fs::read_to_string(home.join("ns/acme/audit.log")).unwrap();
    let default_log = std::fs::read_to_string(home.join("audit.log")).unwrap();
    assert!(acme_log.contains("ok: gh") && !default_log.contains("ok: gh"));

    drop((_lock_acme, _lock_default, _lock_other));
    assert!(
        wait_until(|| !home.join("ns/acme/sock").exists()),
        "acme daemon still running"
    );
    std::fs::remove_dir_all(&base).unwrap();
}
