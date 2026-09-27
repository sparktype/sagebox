// 에이전트에게 비밀 정보를 안전하게 전달하는 secretbox 데몬 진입점
mod admin;
mod audit;
#[cfg(unix)]
mod client;
#[cfg(unix)]
mod daemon;
mod namespace;
#[cfg(unix)]
mod prompt;
mod vault;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use namespace::Ns;

use vault::Result;

const USAGE: &str = "usage: secretbox [--ns <namespace>] <command>
  secretbox ns
  secretbox trust | untrust [dir]
  secretbox init
  secretbox set <name> [--expires YYYY-MM-DD]
  secretbox rm <name>
  secretbox list
  secretbox audit verify
  secretbox profile add <name> [--env ENV=secret]... -- <absolute-command> [args]...
  secretbox profile rm <name>
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
    let (flag, args) = match args {
        ["--ns", name, rest @ ..] => (Some(*name), rest),
        _ => (None, args),
    };
    let root = data_root()?;
    let cwd = std::env::current_dir()?;
    let (name, source, project) =
        namespace::resolve(flag, std::env::var("SECRETBOX_NS").ok(), &cwd)?;
    let ns = Ns {
        dir: namespace::dir(&root, &name),
        name,
        source,
        project,
    };
    create_private_dir(&ns.dir)?;
    let dir = &ns.dir;
    let vault = dir.join("vault");
    match args {
        ["ns"] => {
            println!("namespace: {} (from {})", ns.name, ns.source);
            println!("available: {}", namespace::list(&root).join(", "));
            Ok(())
        }
        ["init"] => admin::init(&vault),
        ["trust"] => {
            let dir = ns.project.as_ref().ok_or(
                "trust needs a .secretbox file naming a non-default namespace in this directory or above",
            )?;
            admin::trust(&vault, dir)?;
            println!("trusted {} for namespace {}", dir.display(), ns.name);
            Ok(())
        }
        ["untrust"] => {
            let dir = ns
                .project
                .as_ref()
                .ok_or("no .secretbox project here; use `untrust <dir>`")?;
            admin::untrust(&vault, &dir.display().to_string())
        }
        ["untrust", dir] => admin::untrust(&vault, dir),
        ["set", name] => admin::set(&vault, name, None),
        ["set", name, "--expires", date] => admin::set(&vault, name, Some(date)),
        ["rm", name] => admin::rm(&vault, name),
        ["list"] => admin::list(&vault),
        ["audit", "verify"] => admin::audit_verify(&vault, &dir.join("audit.log")),
        ["profile", "add", name, rest @ ..] => {
            let (env, command) = parse_profile_args(rest)?;
            admin::profile_add(&vault, name, env, command)
        }
        ["profile", "rm", name] => admin::profile_rm(&vault, name),
        #[cfg(unix)]
        ["daemon"] => daemon::serve(dir),
        #[cfg(unix)]
        ["unlock"] => client::unlock(&ns),
        #[cfg(unix)]
        ["lock"] => client::lock(&ns),
        #[cfg(unix)]
        ["status"] => client::status(&ns),
        #[cfg(unix)]
        ["exec", profile] => client::exec(&ns, profile),
        #[cfg(not(unix))]
        ["daemon" | "unlock" | "lock" | "status"] | ["exec", _] => {
            Err("not supported on this platform yet".into())
        }
        _ => Err(USAGE.into()),
    }
}

/// `$SECRETBOX_HOME` 또는 `~/.secretbox`. default 네임스페이스는 이 디렉터리를 그대로 쓴다.
fn data_root() -> Result<PathBuf> {
    Ok(match std::env::var_os("SECRETBOX_HOME") {
        Some(d) => PathBuf::from(d),
        None => std::env::home_dir()
            .ok_or("cannot find home directory")?
            .join(".secretbox"),
    })
}

/// 없으면 만든다. Unix는 중간 디렉터리까지 0700.
fn create_private_dir(dir: &Path) -> Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)?;
    Ok(())
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
