# sagebox

<p align="center"><img src="docs/banner.svg" alt="sagebox — private secret vault for AI agents" width="100%"></p>

<p align="center"><b>English</b> · <a href="README.ko.md">한국어</a></p>

**A private secret vault for AI agents.** Instead of keeping API keys and passwords in plain text in `.envrc` or MCP config files, sagebox stores them in an encrypted vault and hands them, as environment variables, only to the programs that need them.

- Secrets never sit on disk in plain text (XChaCha20-Poly1305 + Argon2id).
- Agents such as Claude Code can see secret **names**, never their **values**.
- You unlock with a passphrase or Touch ID, and every use is recorded in a tamper-evident audit log.
- One small Rust binary. It never opens a network port.

> sagebox is a **secret hygiene** tool. It prevents accidents like committing a plaintext `.envrc` or leaking a key into a chat transcript. It does not isolate you from malicious programs running under your own user account. See the threat model in [SPEC.md](SPEC.md) (Korean) for details.

---

## Contents

1. [Why?](#why)
2. [Install](#install)
3. [Five-minute tour](#five-minute-tour)
4. [Usage](#usage)
5. [How it works](#how-it-works)
6. [Code layout](#code-layout)
7. [Changing the code](#changing-the-code)
8. [Troubleshooting](#troubleshooting)

---

## Why?

Secrets usually end up like this:

```sh
# .envrc  ← commit it by accident and the key is public
export OPENAI_API_KEY=sk-real-key...
```

```json
// ~/.claude.json  ← the token sits in plain text in the MCP config
"github": { "command": "npx", "env": { "GITHUB_TOKEN": "ghp_real-token..." } }
```

With sagebox they look like this:

```sh
# .envrc holds no secrets. The vault injects them into this one command.
sagebox run -- npm run dev
```

```json
// The MCP config only says "run it through sagebox"
"github": { "command": "/opt/homebrew/bin/sagebox", "args": ["exec", "github"] }
```

---

## Install

sagebox runs on macOS and Linux (Windows currently only compiles).

### Homebrew (recommended)

```sh
brew install sparktype/tap/sagebox
sagebox          # prints usage if the install worked
```

Homebrew builds sagebox from source, so the first install also pulls in Rust as a build dependency. Upgrade later with `brew upgrade sagebox`.

### From source with Cargo

You need [Rust](https://rustup.rs) 1.85 or newer (check with `rustc --version`).

```sh
cargo install --git https://github.com/sparktype/sagebox
```

The binary goes to `~/.cargo/bin/sagebox`, which must be on your `PATH`. If you later switch to Homebrew, run `cargo uninstall sagebox` first so the old copy does not shadow the new one.

---

## Five-minute tour

### 1) Create a vault

```sh
sagebox init
# new passphrase:     ← at least 8 characters. If you forget it, it cannot be recovered!
# repeat passphrase:
```

### 2) Add a secret

```sh
sagebox set gh
# passphrase:          ← the vault passphrase
# value for gh:        ← the value to store (not echoed)

sagebox list           # shows names only; values are never printed
```

You can set an expiry date. Expired secrets are never handed out.

```sh
sagebox set gh --expires 2027-01-01
```

### 3) (macOS) Turn on Touch ID

```sh
sagebox touchid enable
```

Now you can unlock with Touch ID (or Apple Watch, or your login password) instead of the passphrase. The passphrase always remains as the recovery path.

### 4) Give an MCP server a secret

```sh
sagebox mcp add github --env GITHUB_TOKEN=gh -- npx -y @modelcontextprotocol/server-github
```

This one command does three things:

1. Pins `npx` to its absolute path right now, so a later `PATH` change cannot swap in another program.
2. Creates a `github` **profile** in the vault. A profile is a rule: "run this command with secret `gh` in the `GITHUB_TOKEN` environment variable."
3. Registers the server with Claude Code via `claude mcp add`.

From now on, when Claude Code starts the github MCP server, sagebox injects the secret. If the vault is locked, a Touch ID prompt appears.

---

## Usage

### Basic commands

| Command | What it does |
|---------|--------------|
| `sagebox init` | Creates a new vault |
| `sagebox set <name> [--expires YYYY-MM-DD]` | Adds or replaces a secret |
| `sagebox rm <name>` | Deletes a secret (refused if a profile uses it) |
| `sagebox list` | Shows secret names, expiry dates and profiles |
| `sagebox unlock` / `lock` / `status` | Unlocks, locks, or shows the session |
| `sagebox audit verify` | Checks that the audit log has not been tampered with |

### Managing MCP servers

| Command | What it does |
|---------|--------------|
| `sagebox mcp add <server> --env VAR=secret -- <command>` | Creates a profile and registers it with Claude Code |
| `sagebox import <mcp.json> [--apply]` | Moves plaintext secrets out of an existing MCP config into the vault. Without `--apply` it only previews |
| `sagebox profile add/rm` | Creates or deletes a profile by hand |
| `sagebox exec <profile>` | Runs a profile with its secrets injected (this is what the MCP config calls) |
| `sagebox mcp serve` | Starts sagebox's own MCP server (see below) |

### Replacing a project's `.envrc`

This moves the secrets you use while developing (`.envrc`, `.env`) into the vault.

```sh
cd ~/my-project
sagebox import-env .envrc            # 1. preview: lists what would move, by name only
sagebox import-env .envrc --apply    # 2. apply: moves secret lines into the vault and deletes them from .envrc
```

- Each project gets its own **namespace** (a separate vault), and a `.sagebox` file is created in the project folder.
- Non-secret lines such as `LOG_LEVEL=debug` stay where they are.
- If a variable is misclassified, keep it with `--keep VAR`.
- If the file was ever committed to git you get a warning. Keys left in git history **must be rotated**.

After that, prefix your debug commands with `sagebox run --`:

```sh
sagebox run -- cargo run
sagebox run -- npm run dev
```

> **Note:** `sagebox run` only works **while the sagebox MCP server is running**, that is, while Claude Code is open in this project. Register it once:
>
> ```sh
> claude mcp add -s user sagebox -- "$(command -v sagebox)" mcp serve
> ```

### Shell hook: check on every `cd`

Add one line to `~/.zshrc` (or `~/.bashrc` for bash):

```sh
eval "$(sagebox zsh)"     # for bash: eval "$(sagebox bash)"
```

Now, when you enter a folder whose `.envrc`/`.env` contains plaintext secrets, you are asked:

```
sagebox: .envrc has plaintext secrets:
  OPENAI_API_KEY [token prefix]
move them into the vault and remove them from .envrc? [y/N]
```

`y` cleans it up exactly like `import-env --apply`. `N` leaves the file alone, and that shell won't ask about that folder again.

### Tab completion

Homebrew installs completions for zsh and bash automatically, so `sagebox <Tab>` lists commands, their options, and namespace names after `--ns`. Secret and profile names are not completed, because reading them would need the passphrase. With a Cargo install, generate the script yourself:

```sh
sagebox completion zsh > "${fpath[1]}/_sagebox"     # zsh (any directory on $fpath), then restart the shell
sagebox completion bash > ~/.local/share/bash-completion/completions/sagebox   # bash
```

### Namespaces (one vault per project)

| How | Example |
|-----|---------|
| Command-line flag | `sagebox --ns acme list` |
| Environment variable | `SAGEBOX_NS=acme sagebox list` |
| Project file | `namespace = "acme"` in a `.sagebox` file in the folder (or a parent) |
| Default | `default` (`~/.sagebox/`) |

Earlier rows take precedence. `sagebox ns` shows which namespace is selected. A namespace chosen by a `.sagebox` file can only be used if that folder was registered with `sagebox trust`. This stops someone from dropping a `.sagebox` file into a folder to pull another project's secrets.

### The sagebox MCP server

`sagebox mcp serve` gives the agent two tools:

- `status`: whether the vault is locked, and how many servers are using its secrets
- `list`: secret names and expiry dates, and the list of profiles

**No tool ever returns a secret value.** `sagebox run` is only allowed while this server is running.

---

## How it works

```
  user ──(passphrase)──▶ admin CLI ──(encrypt & save)──▶ vault file (~/.sagebox/vault)
                                                            ▲
  user ──(unlock / Touch ID)──▶ daemon ──(open with DEK)────┘
                                 │ ▲
                (argv + env)     ▼ │ (request)
  agent ──(spawn)──▶ sagebox exec ──(execve)──▶ MCP server (secrets live only in its env)
```

Four key ideas:

1. **Envelope encryption.** The vault body is encrypted with a random key (the DEK), and the DEK is stored in "slots" opened by a passphrase or Touch ID. Adding a slot never requires re-encrypting the body.
2. **Admin commands bypass the daemon.** Commands like `set`, `rm` and `profile add` open the vault file directly with the passphrase every time. So even while a session is unlocked, an agent cannot change the rules.
3. **The daemon lives only when needed.** The first `exec` or `unlock` starts it automatically. It keeps only the DEK in memory, and wipes it and exits 30 seconds after the last MCP server ends, after 8 hours, or when the system sleeps or the screen locks.
4. **Leases.** `exec` hands its daemon socket down to the MCP server process across `execve`. When that socket closes, the daemon knows the server has ended.

For pictures, open [`docs/diagrams/architecture.html`](docs/diagrams/architecture.html) in a browser. Design decisions and their reasons are in [`SPEC.md`](SPEC.md) and [`context-notes.md`](context-notes.md) (both in Korean).

---

## Code layout

```
src/
├── main.rs        entry point: parses arguments and dispatches (USAGE, the match)
├── vault.rs       vault file format: encrypt/decrypt, slots, the Vault struct
├── admin.rs       admin commands: init, set, rm, list, profile, trust, audit verify
├── namespace.rs   decides which namespace to use
├── daemon.rs      daemon: holds the session (DEK), handles requests, leases, auto-exit
├── client.rs      talks to the daemon: unlock, lock, status, exec, run
├── audit.rs       audit log (a MAC chain over each line)
├── mcp.rs         sagebox mcp add
├── mcp_server.rs  sagebox mcp serve (stdio JSON-RPC)
├── import.rs      MCP config import + the secret classifier (classify)
├── envfile.rs     .envrc import, sagebox env, shell hook
├── prompt.rs      GUI passphrase prompt (osascript / zenity / kdialog / pinentry)
├── touchid.rs     Touch ID slot management (macOS)
├── macos.rs       macOS system calls (screen lock, Secure Enclave)
└── debug.rs       debug log, only with SAGEBOX_DEBUG=1
tests/cli.rs       integration tests that run the real binary
```

Every source file starts with a one-line comment (in Korean) stating its role. If you don't know where to start, skim them with `head -1 src/*.rs`.

**Suggested reading order:** `main.rs` (which command goes where) → `list` in `admin.rs` (the simplest command) → the `Vault` struct in `vault.rs` → `exec` in `client.rs` → `handle` in `daemon.rs`.

---

## Changing the code

### 1. Build and test

```sh
cargo build                                  # debug build → target/debug/sagebox
cargo test                                   # all tests
cargo test hook_check                        # only tests whose name contains hook_check
cargo clippy --all-targets -- -D warnings    # fails on any warning
cargo fmt                                    # format the code
```

Also check that it still compiles for Linux and Windows (install the targets once):

```sh
rustup target add x86_64-unknown-linux-gnu x86_64-pc-windows-msvc
cargo check --all-targets --target x86_64-unknown-linux-gnu
cargo check --all-targets --target x86_64-pc-windows-msvc
```

**Before you finish a change, all four must pass: test, clippy, fmt and the cross-compile checks.**

### 2. Experiment without touching your real vault

Point `SAGEBOX_HOME` at a scratch folder:

```sh
export SAGEBOX_HOME=/tmp/sbx-play
export SAGEBOX_NO_GUI=1          # ask in the terminal instead of a GUI dialog
export SAGEBOX_DEBUG=1           # log decisions to stderr and debug.log

./target/debug/sagebox init
printf 'mypassword\nsecret-value\n' | ./target/debug/sagebox set demo
```

When stdin is not a terminal (a pipe), passphrases and values are read **one line at a time, in order**, from stdin. The tests rely on this.

### 3. Example: adding a command

Say you want `sagebox count`, which prints how many secrets there are.

**① Write the function** (`src/admin.rs`)

```rust
/// Prints the number of secrets. Never prints values.
pub fn count(path: &Path) -> Result<()> {
    let (_, v, _) = unlock(path)?;          // open the vault with the passphrase
    println!("{}", v.secrets.len());
    Ok(())
}
```

**② Wire up the command** (`src/main.rs`)

Add a line to the `USAGE` string, and a branch inside `match args`:

```rust
        ["count"] => admin::count(&vault),
```

**③ Write a test** (`tests/cli.rs`)

```rust
#[test]
fn count_secrets() {
    let home = std::env::temp_dir().join(format!("sbx-count-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    assert!(sbx(&home, "password\npassword\n", &["init"]).status.success());
    assert!(sbx(&home, "password\nv1\n", &["set", "a"]).status.success());

    let o = sbx(&home, "password\n", &["count"]);
    assert_eq!(String::from_utf8_lossy(&o.stdout), "1\n");
    std::fs::remove_dir_all(&home).unwrap();
}
```

`sbx(home, stdin, args)` is a test helper. It runs the binary with a temporary `SAGEBOX_HOME` and feeds the `stdin` string as input, one line per prompt.

**④ Check**

```sh
cargo test count_secrets
cargo clippy --all-targets -- -D warnings && cargo fmt
```

**⑤ Update the docs**: record design changes in `SPEC.md`, progress in `checklist.md`, and the reasons behind decisions in `context-notes.md`. If the flow changed, update `docs/diagrams/architecture.html` too.

### 4. Rules to follow

| Rule | Why |
|------|-----|
| Keep secret values in `Zeroizing<String>`, and never print, log or `Debug`-format them | So they are wiped from memory and never land on screen or in logs |
| Never invent cryptography. Use only vetted RustCrypto crates | Hand-rolled crypto is almost always broken |
| Add a dependency only when truly needed, and justify it | To keep one small binary |
| Never open a network port. Communicate only over a Unix socket with mode 0600 | So other users and remote hosts cannot reach it |
| Wrap platform-specific code in `#[cfg(unix)]` or `#[cfg(target_os = "macos")]` | So the Windows build does not break |
| Preserve slots of unknown kinds as-is | So a slot added on another machine (e.g. Touch ID) is not erased |
| Start every new source file with a one-line Korean comment stating its role | So anyone opening the file knows what it is at a glance |

### 5. Commit messages

Use the `<type>(<scope>): <description>` format:

```
feat(hook): shell hook that finds plaintext secrets in .envrc on cd and offers to clean them
fix(client): report an over-long socket path before starting the daemon
docs(readme): add a beginner's guide
```

Types: `feat` (feature), `fix` (bug fix), `docs` (documentation), `refactor` (cleanup with no behavior change), `test` (tests), `chore` (everything else).

### 6. Testing Touch ID

Touch ID needs a human finger, so it is excluded from the default test run.

```sh
cargo test se_roundtrip -- --ignored     # you must answer the system dialog yourself
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `locked: run sagebox unlock` | Unlock the session with `sagebox unlock` |
| `no sagebox MCP server is running` | Open Claude Code in this project, and check `claude mcp list` shows the sagebox MCP server |
| `project ... is not trusted` | Run `sagebox trust` in that project folder (needs the passphrase) |
| `socket path is too long` | Set `SAGEBOX_HOME` to a shorter path |
| `secret X expired on ...` | Store a new value with `sagebox set X --expires <new date>` |
| Not sure what went wrong | Re-run with `SAGEBOX_DEBUG=1` and read `~/.sagebox/debug.log` |
| A daemon is left over after a failed test | It exits on its own within 2–10 minutes |

**If you forget your passphrase**, it cannot be recovered. That is by design. With a Touch ID slot you can still `unlock`, `exec` and `run`, but admin commands such as `set`, `rm` and `profile` need the passphrase. Rotate your secrets and move them into a new vault (`sagebox init`).

---

## License

[MIT](LICENSE) © 2026 SangSun Park. You are free to use, modify and redistribute sagebox, including commercially, as long as you keep the copyright notice and license text.
