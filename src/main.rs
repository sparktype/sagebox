// 에이전트에게 비밀 정보를 안전하게 전달하는 sagebox 데몬 진입점
mod admin;
mod audit;
#[cfg(unix)]
mod client;
#[cfg(unix)]
mod daemon;
#[cfg(unix)]
mod debug;
mod envfile;
mod import;
#[cfg(target_os = "macos")]
mod macos;
mod mcp;
#[cfg(unix)]
mod mcp_server;
mod namespace;
#[cfg(unix)]
mod prompt;
#[cfg(target_os = "macos")]
mod touchid;
mod vault;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use namespace::Ns;

use vault::Result;

const USAGE: &str = "usage: sagebox [--ns <namespace>] <command>
  sagebox ns
  sagebox trust | untrust [dir]
  sagebox init
  sagebox set <name> [--expires YYYY-MM-DD]
  sagebox rm <name>
  sagebox list
  sagebox audit verify
  sagebox import <mcp.json> [--keep VAR]... [--apply]
  sagebox import-env <.envrc|.env> [--keep VAR]... [--apply]
  sagebox env [--print]            (for .envrc: eval \"$(sagebox env)\")
  sagebox mcp serve                (stdio MCP server: secret names, profiles, lock status)
  sagebox mcp add <server> [--env ENV=secret]... [--scope local|user|project] -- <command> [args]...
  sagebox profile add <name> [--env ENV=secret]... -- <absolute-command> [args]...
  sagebox profile rm <name>
  sagebox unlock [--passphrase] | lock | status
  sagebox touchid enable | disable | status   (macOS)
  sagebox exec <profile>
  sagebox run -- <command> [args]...  (project env; only while the sagebox MCP server runs)";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args.iter().map(String::as_str).collect::<Vec<_>>()) {
        eprintln!("sagebox: {e}");
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
    let (name, source, project) = namespace::resolve(flag, std::env::var("SAGEBOX_NS").ok(), &cwd)?;
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
                "trust needs a .sagebox file naming a non-default namespace in this directory or above",
            )?;
            admin::trust(&vault, dir)?;
            println!("trusted {} for namespace {}", dir.display(), ns.name);
            Ok(())
        }
        ["untrust"] => {
            let dir = ns
                .project
                .as_ref()
                .ok_or("no .sagebox project here; use `untrust <dir>`")?;
            admin::untrust(&vault, &dir.display().to_string())
        }
        ["untrust", dir] => admin::untrust(&vault, dir),
        ["set", name] => admin::set(&vault, name, None),
        ["set", name, "--expires", date] => admin::set(&vault, name, Some(date)),
        ["rm", name] => admin::rm(&vault, name),
        ["list"] => admin::list(&vault),
        ["import-env", file, flags @ ..] => {
            let (mut keep, mut apply) = (vec![], false);
            let mut it = flags.iter();
            while let Some(f) = it.next() {
                match *f {
                    "--apply" => apply = true,
                    "--keep" => keep.push(*it.next().ok_or("--keep needs a variable name")?),
                    _ => return Err(USAGE.into()),
                }
            }
            envfile::import(&root, Path::new(file), &keep, apply)
        }
        #[cfg(unix)]
        ["env"] => envfile::export(&ns, false),
        #[cfg(unix)]
        ["env", "--print"] => envfile::export(&ns, true),
        ["import", file, flags @ ..] => {
            let (mut keep, mut apply) = (vec![], false);
            let mut it = flags.iter();
            while let Some(f) = it.next() {
                match *f {
                    "--apply" => apply = true,
                    "--keep" => keep.push(*it.next().ok_or("--keep needs a variable name")?),
                    _ => return Err(USAGE.into()),
                }
            }
            let ns_args = match ns.name.as_str() {
                namespace::DEFAULT => vec![],
                name => vec!["--ns".to_string(), name.to_string()],
            };
            import::run(&vault, Path::new(file), &keep, apply, &ns_args)
        }
        ["audit", "verify"] => admin::audit_verify(&vault, &dir.join("audit.log")),
        ["profile", "add", name, rest @ ..] => {
            let (env, command) = parse_profile_args(rest)?;
            admin::profile_add(&vault, name, env, command)
        }
        #[cfg(unix)]
        ["mcp", "serve"] => mcp_server::serve(&ns),
        ["mcp", "add", server, rest @ ..] => {
            // --scope만 떼어 내고 나머지는 profile add와 같은 형식으로 읽는다.
            let dash = rest.iter().position(|a| *a == "--").unwrap_or(rest.len());
            let mut opts = rest[..dash].to_vec();
            let mut scope = "user";
            if let Some(i) = opts.iter().position(|a| *a == "--scope") {
                scope = opts.get(i + 1).ok_or("--scope needs a value")?;
                opts.drain(i..i + 2);
            }
            let (env, command) = parse_profile_args(&[opts, rest[dash..].to_vec()].concat())?;
            mcp::add(&vault, &ns.name, server, env, command, scope)
        }
        ["profile", "rm", name] => admin::profile_rm(&vault, name),
        #[cfg(unix)]
        ["daemon"] => daemon::serve(dir),
        #[cfg(unix)]
        ["unlock"] => client::unlock(&ns, false),
        #[cfg(unix)]
        ["unlock", "--passphrase"] => client::unlock(&ns, true),
        #[cfg(target_os = "macos")]
        ["touchid", "enable"] => touchid::enable(&vault),
        #[cfg(target_os = "macos")]
        ["touchid", "disable"] => touchid::disable(&vault),
        #[cfg(target_os = "macos")]
        ["touchid", "status"] => touchid::status(&vault),
        #[cfg(not(target_os = "macos"))]
        ["touchid", ..] => Err("Touch ID is only available on macOS".into()),
        #[cfg(unix)]
        ["lock"] => client::lock(&ns),
        #[cfg(unix)]
        ["status"] => client::status(&ns),
        #[cfg(unix)]
        ["exec", profile] => client::exec(&ns, profile),
        #[cfg(unix)]
        ["run", "--", command @ ..] => client::run(&ns, command),
        #[cfg(not(unix))]
        ["daemon" | "unlock" | "lock" | "status"]
        | ["exec", _]
        | ["mcp", "serve"]
        | ["run", ..] => Err("not supported on this platform yet".into()),
        _ => Err(USAGE.into()),
    }
}

/// `$SAGEBOX_HOME` 또는 `~/.sagebox`. default 네임스페이스는 이 디렉터리를 그대로 쓴다.
fn data_root() -> Result<PathBuf> {
    Ok(match std::env::var_os("SAGEBOX_HOME") {
        Some(d) => PathBuf::from(d),
        None => std::env::home_dir()
            .ok_or("cannot find home directory")?
            .join(".sagebox"),
    })
}

/// 없으면 만든다. Unix는 중간 디렉터리까지 0700.
pub(crate) fn create_private_dir(dir: &Path) -> Result<()> {
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
