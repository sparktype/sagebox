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
