// 에이전트에게 비밀 정보를 안전하게 전달하는 secretbox 데몬 진입점
mod admin;
#[cfg(unix)]
mod client;
#[cfg(unix)]
mod daemon;
mod vault;

use std::collections::BTreeMap;
use std::path::PathBuf;

use vault::Result;

const USAGE: &str = "usage:
  secretbox init
  secretbox set <name> [--expires YYYY-MM-DD]
  secretbox rm <name>
  secretbox list
  secretbox profile add <name> [--env ENV=secret]... -- <absolute-command> [args]...
  secretbox profile rm <name>
  secretbox daemon
  secretbox unlock | lock | status
  secretbox exec <profile>";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args.iter().map(String::as_str).collect::<Vec<_>>()) {
        eprintln!("secretbox: {e}");
        std::process::exit(1);
    }
}

fn run(args: &[&str]) -> Result<()> {
    let dir = data_dir()?;
    let vault = dir.join("vault");
    match args {
        ["init"] => admin::init(&vault),
        ["set", name] => admin::set(&vault, name, None),
        ["set", name, "--expires", date] => admin::set(&vault, name, Some(date)),
        ["rm", name] => admin::rm(&vault, name),
        ["list"] => admin::list(&vault),
        ["profile", "add", name, rest @ ..] => {
            let (env, command) = parse_profile_args(rest)?;
            admin::profile_add(&vault, name, env, command)
        }
        ["profile", "rm", name] => admin::profile_rm(&vault, name),
        #[cfg(unix)]
        ["daemon"] => daemon::serve(&dir),
        #[cfg(unix)]
        ["unlock"] => client::unlock(&dir),
        #[cfg(unix)]
        ["lock"] => client::lock(&dir),
        #[cfg(unix)]
        ["status"] => client::status(&dir),
        #[cfg(unix)]
        ["exec", profile] => client::exec(&dir, profile),
        #[cfg(not(unix))]
        ["daemon" | "unlock" | "lock" | "status"] | ["exec", _] => {
            Err("not supported on this platform yet".into())
        }
        _ => Err(USAGE.into()),
    }
}

/// `$SECRETBOX_HOME` 또는 `~/.secretbox`. 없으면 만든다 (Unix는 0700).
fn data_dir() -> Result<PathBuf> {
    let dir = match std::env::var_os("SECRETBOX_HOME") {
        Some(d) => PathBuf::from(d),
        None => std::env::home_dir()
            .ok_or("cannot find home directory")?
            .join(".secretbox"),
    };
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&dir)?;
    Ok(dir)
}

/// `[--env ENV=secret]... -- <command>...`
fn parse_profile_args(rest: &[&str]) -> Result<(BTreeMap<String, String>, Vec<String>)> {
    let mut env = BTreeMap::new();
    let mut it = rest.iter();
    loop {
        match it.next() {
            Some(&"--env") => {
                let (k, v) = it
                    .next()
                    .and_then(|kv| kv.split_once('='))
                    .ok_or("--env needs ENV=secret")?;
                env.insert(k.to_string(), v.to_string());
            }
            Some(&"--") => break,
            _ => return Err(USAGE.into()),
        }
    }
    Ok((env, it.map(|s| s.to_string()).collect()))
}
