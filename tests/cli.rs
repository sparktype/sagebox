// 임시 SAGEBOX_HOME에서 관리 CLI 흐름(init → set → profile → list/rm)을 실행해 보는 통합 테스트
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn sbx(home: &Path, stdin: &str, args: &[&str]) -> Output {
    sbx_in(Path::new("."), home, stdin, args)
}

/// cwd에서 실행한다. 네임스페이스는 cwd 위의 .sagebox 파일로도 정해진다.
fn sbx_in(cwd: &Path, home: &Path, stdin: &str, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sagebox"))
        .args(args)
        .current_dir(cwd)
        .env("SAGEBOX_HOME", home)
        .env("SAGEBOX_NO_GUI", "1")
        .env("SAGEBOX_NO_AUTOLOCK", "1")
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
    assert!(stderr(&o).contains("sagebox unlock"), "{}", stderr(&o));
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
    let mut sleeper = Command::new(env!("CARGO_BIN_EXE_sagebox"))
        .args(["exec", "sleeper"])
        .env("SAGEBOX_HOME", &home)
        .env("SAGEBOX_NO_GUI", "1")
        .env("SAGEBOX_NO_AUTOLOCK", "1")
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
    assert!(
        audit.contains("denied (passphrase): wrong passphrase")
            && audit.contains(r#""op":"release""#)
    );
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
    std::fs::write(base.join("acme-repo/.sagebox"), "namespace = \"acme\"\n").unwrap();
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
    assert!(stdout(&o).contains("namespace: acme (from ") && stdout(&o).contains(".sagebox)"));
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
        stderr(&o).contains("locked: run `sagebox unlock`"),
        "{}",
        stderr(&o)
    );
    let o = sbx_in(&project, &home, "", &["--ns", "default", "exec", "github"]);
    assert!(stderr(&o).contains("locked"), "{}", stderr(&o));
    assert!(stdout(&sbx_in(&project, &home, "", &["status"])).starts_with("acme: unlocked"));

    // 저장소가 .sagebox를 다른 네임스페이스로 바꾸면 그쪽 신뢰 목록에는 없으므로 거부된다.
    ok(sbx(
        &home,
        "otherpass\notherpass\n",
        &["--ns", "other", "init"],
    ));
    ok(sbx(&home, "otherpass\n", &["--ns", "other", "unlock"]));
    let _lock_other = LockOnDrop(home.clone(), "other");
    std::fs::write(base.join("acme-repo/.sagebox"), "namespace = \"other\"\n").unwrap();
    let o = sbx_in(&project, &home, "", &["exec", "github"]);
    assert!(stderr(&o).contains("is not trusted"), "{}", stderr(&o));
    std::fs::write(base.join("acme-repo/.sagebox"), "namespace = \"acme\"\n").unwrap();

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

#[cfg(unix)]
#[test]
fn import_mcp_config() {
    use std::os::unix::fs::PermissionsExt;

    let base = std::env::temp_dir().join(format!("sbx-imp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let home = base.join("home");
    let _cleanup = LockOnDrop(home.clone(), "default");
    let ok = |o: Output| assert!(o.status.success(), "{}", stderr(&o));
    let stdout = |o: &Output| String::from_utf8_lossy(&o.stdout).into_owned();
    ok(sbx(&home, "password\npassword\n", &["init"]));

    let cfg = base.join("mcp.json");
    let original = r#"{
  "mcpServers": {
    "github": {"command": "env", "args": [], "env": {"GITHUB_TOKEN": "ghp_testtoken1234567890abcdef", "LOG_LEVEL": "info"}},
    "slack": {"command": "env", "env": {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T0/B0/xyz"}},
    "plain": {"command": "env", "args": ["-0"]},
    "odd": {"command": "env", "env": {"SENTRY_DSN": "https://abc123@o1.ingest.sentry.io/42"}}
  },
  "other": {"keep": true}
}"#;
    std::fs::write(&cfg, original).unwrap();
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o644)).unwrap();
    let cfg_s = cfg.to_str().unwrap();

    // 미리보기: 아무것도 바꾸지 않고, 값은 출력하지 않는다.
    let o = sbx(&home, "", &["import", cfg_s]);
    let out = stdout(&o);
    assert!(
        out.contains("GITHUB_TOKEN -> secret github.GITHUB_TOKEN [token prefix]"),
        "{out}"
    );
    assert!(out.contains("LOG_LEVEL stays in config") && out.contains("plain: no secrets"));
    assert!(
        out.contains("SENTRY_DSN -> secret odd.SENTRY_DSN [unsure]") && out.contains("dry run")
    );
    assert!(
        !out.contains("ghp_") && !out.contains("hooks.slack.com"),
        "values leaked: {out}"
    );
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), original);

    // 적용: 애매한 SENTRY_DSN은 --keep으로 설정에 남긴다.
    let o = sbx(
        &home,
        "password\n",
        &["import", cfg_s, "--keep", "SENTRY_DSN", "--apply"],
    );
    assert!(
        stdout(&o).contains("imported 2 secrets"),
        "{}{}",
        stdout(&o),
        stderr(&o)
    );
    let text = std::fs::read_to_string(&cfg).unwrap();
    assert!(
        !text.contains("ghp_") && !text.contains("hooks.slack.com"),
        "{text}"
    );
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let gh = &v["mcpServers"]["github"];
    assert!(gh["command"].as_str().unwrap().ends_with("sagebox"));
    assert_eq!(gh["args"], serde_json::json!(["exec", "github"]));
    assert_eq!(gh["env"], serde_json::json!({"LOG_LEVEL": "info"}));
    assert!(v["mcpServers"]["slack"].get("env").is_none());
    assert_eq!(v["mcpServers"]["odd"]["command"], "env");
    assert_eq!(v["other"]["keep"], true);
    let mode = std::fs::metadata(&cfg).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o644, "permissions not preserved");

    // 다시 실행하면 이미 관리 중이라 건너뛴다.
    let out = stdout(&sbx(&home, "", &["import", cfg_s]));
    assert!(out.contains("github: already managed by sagebox"), "{out}");

    // 옮긴 비밀이 실제로 exec에 주입된다.
    ok(sbx(&home, "password\n", &["unlock"]));
    let o = sbx(&home, "", &["exec", "github"]);
    assert!(
        stdout(&o).contains("GITHUB_TOKEN=ghp_testtoken1234567890abcdef"),
        "{}",
        stderr(&o)
    );

    drop(_cleanup);
    std::fs::remove_dir_all(&base).unwrap();
}

/// PATH 앞에 가짜 `claude`를 두고 실행한다. 가짜 claude는 받은 인자를 한 줄에 하나씩 기록한다.
#[cfg(unix)]
fn sbx_with_fake_claude(home: &Path, bin: &Path, stdin: &str, args: &[&str]) -> Output {
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let mut child = Command::new(env!("CARGO_BIN_EXE_sagebox"))
        .args(args)
        .env("SAGEBOX_HOME", home)
        .env("SAGEBOX_NO_GUI", "1")
        .env("SAGEBOX_NO_AUTOLOCK", "1")
        .env("PATH", path)
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

#[cfg(unix)]
#[test]
fn mcp_add_registers_with_claude() {
    use std::os::unix::fs::PermissionsExt;

    let base = std::env::temp_dir().join(format!("sbx-mcp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (home, bin) = (base.join("home"), base.join("bin"));
    std::fs::create_dir_all(&bin).unwrap();
    let log = base.join("claude-args");
    let fake = format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", log.display());
    std::fs::write(bin.join("claude"), fake).unwrap();
    std::fs::set_permissions(bin.join("claude"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let _cleanup = LockOnDrop(home.clone(), "default");
    let ok = |o: Output| assert!(o.status.success(), "{}", stderr(&o));
    let stdout = |o: &Output| String::from_utf8_lossy(&o.stdout).into_owned();
    let sagebox = std::fs::canonicalize(env!("CARGO_BIN_EXE_sagebox")).unwrap();
    ok(sbx(&home, "password\npassword\n", &["init"]));

    // 없는 비밀(demo_token)은 패스프레이즈 다음에 그 자리에서 입력받는다. 명령 `env`는 절대경로로 고정된다.
    let o = sbx_with_fake_claude(
        &home,
        &bin,
        "password\nfake-token-value\n",
        &[
            "mcp",
            "add",
            "demo",
            "--env",
            "DEMO_TOKEN=demo_token",
            "--",
            "env",
            "-0",
        ],
    );
    let out = stdout(&o);
    assert!(o.status.success(), "{}{}", out, stderr(&o));
    assert!(
        out.contains("profile demo -> /usr/bin/env -0") && out.contains("scope: user"),
        "{out}"
    );
    assert!(
        out.contains("\"exec\"") && !out.contains("fake-token-value"),
        "{out}"
    );
    let args: Vec<String> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    let want = [
        "mcp",
        "add",
        "-s",
        "user",
        "demo",
        "--",
        sagebox.to_str().unwrap(),
        "exec",
        "demo",
    ];
    assert_eq!(args, want);
    let listed = stdout(&sbx(&home, "password\n", &["list"]));
    assert!(
        listed.contains("demo_token")
            && listed.contains("demo: [DEMO_TOKEN=demo_token] /usr/bin/env -0")
    );

    // 이미 있는 프로필은 거부한다.
    let o = sbx_with_fake_claude(
        &home,
        &bin,
        "password\n",
        &["mcp", "add", "demo", "--", "env"],
    );
    assert!(stderr(&o).contains("profile demo already exists"));

    // 이름 있는 네임스페이스는 --ns를 붙여 등록하고, --scope를 따른다.
    ok(sbx(
        &home,
        "acmepass1\nacmepass1\n",
        &["--ns", "acme", "init"],
    ));
    let o = sbx_with_fake_claude(
        &home,
        &bin,
        "acmepass1\nacme-value\n",
        &[
            "--ns",
            "acme",
            "mcp",
            "add",
            "gh",
            "--scope",
            "project",
            "--env",
            "GH_TOKEN=gh",
            "--",
            "env",
        ],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let args: Vec<String> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    let want = [
        "mcp",
        "add",
        "-s",
        "project",
        "gh",
        "--",
        sagebox.to_str().unwrap(),
        "--ns",
        "acme",
        "exec",
        "gh",
    ];
    assert_eq!(args, want);

    drop(_cleanup);
    std::fs::remove_dir_all(&base).unwrap();
}

#[cfg(unix)]
#[test]
fn import_envrc_and_export() {
    let base = std::env::temp_dir().join(format!("sbx-envrc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (home, project) = (base.join("home"), base.join("demo-proj"));
    std::fs::create_dir_all(&project).unwrap();
    let envrc = project.join(".envrc");
    let original = "# demo\nexport OPENAI_API_KEY=sk-FAKEvalue123\nexport LOG_LEVEL=debug\nexport URL=\"https://$HOST/api\"\nlayout python\nexport DB_URL=postgres://u:pw@db/app\n";
    std::fs::write(&envrc, original).unwrap();
    let stdout = |o: &Output| String::from_utf8_lossy(&o.stdout).into_owned();
    let envrc_s = envrc.to_str().unwrap();

    // 미리보기: 이름만 보이고 파일은 그대로다.
    let out = stdout(&sbx(&home, "", &["import-env", envrc_s]));
    assert!(out.contains("namespace: demo-proj (new"), "{out}");
    assert!(
        out.contains("OPENAI_API_KEY -> vault [token prefix]")
            && out.contains("DB_URL -> vault [URL with password]")
    );
    assert!(out.contains("URL stays (computed by the shell)") && !out.contains("LOG_LEVEL ->"));
    assert!(
        !out.contains("sk-FAKE") && !out.contains("u:pw"),
        "values leaked: {out}"
    );
    assert_eq!(std::fs::read_to_string(&envrc).unwrap(), original);

    // 적용: 새 네임스페이스라 새 패스프레이즈를 두 번 받는다.
    let o = sbx(
        &home,
        "projpass1\nprojpass1\n",
        &["import-env", envrc_s, "--apply"],
    );
    assert!(
        stdout(&o).contains("moved 2 secrets into namespace demo-proj"),
        "{}{}",
        stdout(&o),
        stderr(&o)
    );
    let rewritten = std::fs::read_to_string(&envrc).unwrap();
    assert_eq!(
        rewritten,
        "# demo\nexport LOG_LEVEL=debug\nexport URL=\"https://$HOST/api\"\nlayout python\n"
    );
    assert_eq!(
        std::fs::read_to_string(project.join(".sagebox")).unwrap(),
        "namespace = \"demo-proj\"\n"
    );
    assert!(home.join("ns/demo-proj/vault").is_file());

    // 프로젝트 안의 sagebox env는 매번 확인(여기서는 패스프레이즈) 후 export 문을 낸다.
    let o = sbx_in(&project, &home, "projpass1\n", &["env"]);
    let out = stdout(&o);
    assert!(
        out.contains("export OPENAI_API_KEY='sk-FAKEvalue123'"),
        "{}",
        stderr(&o)
    );
    assert!(out.contains("export DB_URL='postgres://u:pw@db/app'") && !out.contains("LOG_LEVEL"));
    assert!(
        !sbx_in(&project, &home, "wrongpass\n", &["env"])
            .status
            .success()
    );

    // 다시 가져오면 이미 내보내는 변수라 거부한다.
    std::fs::write(&envrc, "export OPENAI_API_KEY=sk-FAKEother999\n").unwrap();
    let o = sbx(&home, "projpass1\n", &["import-env", envrc_s, "--apply"]);
    assert!(
        stderr(&o).contains("already exported by namespace demo-proj"),
        "{}",
        stderr(&o)
    );

    std::fs::remove_dir_all(&base).unwrap();
}

#[cfg(unix)]
#[test]
fn mcp_serve_lists_names_only() {
    let home = std::env::temp_dir().join(format!("sbx-ms-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let _cleanup = LockOnDrop(home.clone(), "default");
    let ok = |o: Output| assert!(o.status.success(), "{}", stderr(&o));
    ok(sbx(&home, "password\npassword\n", &["init"]));
    ok(sbx(&home, "password\nghp_secret\n", &["set", "gh"]));
    let args = [
        "profile",
        "add",
        "github",
        "--env",
        "GITHUB_TOKEN=gh",
        "--",
        "/usr/bin/env",
    ];
    ok(sbx(&home, "password\n", &args));

    let session = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list","arguments":{}}}
"#;
    let call = || {
        let o = sbx(&home, session, &["mcp", "serve"]);
        assert!(o.status.success(), "{}", stderr(&o));
        let replies: Vec<serde_json::Value> = String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(replies.len(), 3, "notifications get no reply");
        assert_eq!(replies[0]["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(replies[1]["result"]["tools"][1]["name"], "list");
        replies[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    };

    // 잠겨 있으면 목록 대신 unlock을 안내한다.
    assert!(call().contains("sagebox unlock"));

    ok(sbx(&home, "password\n", &["unlock", "--passphrase"]));
    let text = call();
    assert!(
        text.contains("\"gh\"") && text.contains("\"GITHUB_TOKEN\""),
        "{text}"
    );
    assert!(
        !text.contains("ghp_secret"),
        "values must never be returned"
    );
}

#[cfg(unix)]
#[test]
fn run_needs_live_mcp_server() {
    let base = std::env::temp_dir().join(format!("sbx-run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (home, project) = (base.join("h"), base.join("runproj"));
    std::fs::create_dir_all(&project).unwrap();
    let _cleanup = LockOnDrop(home.clone(), "runproj");
    let envrc = project.join(".envrc");
    std::fs::write(&envrc, "export OPENAI_API_KEY=sk-FAKEvalue123\n").unwrap();
    let o = sbx(
        &home,
        "projpass1\nprojpass1\n",
        &["import-env", envrc.to_str().unwrap(), "--apply"],
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let run = || sbx_in(&project, &home, "", &["run", "--", "/usr/bin/env"]);

    // MCP 서버가 없으면 잠금 해제를 묻지도 않고 거부한다.
    assert!(stderr(&run()).contains("no sagebox MCP server"));

    let mut serve = Command::new(env!("CARGO_BIN_EXE_sagebox"))
        .args(["mcp", "serve"])
        .current_dir(&project)
        .env("SAGEBOX_HOME", &home)
        .env("SAGEBOX_NO_GUI", "1")
        .env("SAGEBOX_NO_AUTOLOCK", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let sock = home.join("ns/runproj/sock");
    assert!(wait_until(|| sock.exists()), "mcp serve did not attach");

    // 잠겨 있으면 GUI로 묻는데 테스트에서는 꺼 두었으니 실패한다.
    let o = run();
    assert!(!o.status.success() && !stderr(&o).contains("no sagebox MCP server"));

    let o = sbx_in(&project, &home, "projpass1\n", &["unlock", "--passphrase"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let o = run();
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("OPENAI_API_KEY=sk-FAKEvalue123"),
        "{}",
        stderr(&o)
    );

    // MCP 서버가 끝나면(stdin EOF) 임대가 풀려 다시 거부한다.
    drop(serve.stdin.take());
    serve.wait().unwrap();
    assert!(wait_until(
        || stderr(&run()).contains("no sagebox MCP server")
    ));

    std::fs::remove_dir_all(&base).unwrap();
}
