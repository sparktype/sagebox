# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

sagebox ("private secret vault for agents"; formerly sagevault, secretbox) is a personal secret-management daemon for AI agents. The package is `sagebox`, the CLI binary is `sgb`, and user-facing paths/env use `sagebox` (`~/.sagebox`, `.sagebox`, `SAGEBOX_*`). The vault magic `SBX2` and audit MAC personas `sbx-audit-*` intentionally keep the old prefix because they are part of the on-disk format. Agents fetch passwords/API keys on demand over a local, authenticated channel and use them for MCP servers or skills. Requirements and design decisions live in `SPEC.md` — read it before implementing a feature, and update it (move items from "설계 초안"/"열린 질문" to "확정된 요구사항") when a decision is made.

Status: vault file format (`src/vault.rs`, envelope encryption: random DEK + key slots) the admin CLI (`src/admin.rs`), the Unix daemon (`src/daemon.rs`) + client (`src/client.rs`: unlock/lock/status/exec), and the MAC-chained audit log (`src/audit.rs`, `sgb audit verify`) are done. Next: hardware key slots (see `checklist.md`). Progress is tracked in `checklist.md`, decision rationale in `context-notes.md`. `docs/diagrams/architecture.html` has architecture / sequence / envelope-format diagrams; update it when the flow changes.

## Commands

```sh
cargo build                      # debug build
cargo build --release            # single small binary at target/release/sgb
cargo test                       # all tests
cargo test <name>                # tests whose path contains <name>
cargo test --test cli            # CLI integration test (tests/cli.rs)
cargo clippy --all-targets -- -D warnings
cargo fmt

# 크로스플랫폼 컴파일 확인 (타깃은 rustup target add로 설치)
cargo check --all-targets --target x86_64-unknown-linux-gnu
cargo check --all-targets --target x86_64-pc-windows-msvc
```

## Testing the CLI

`SAGEBOX_HOME` overrides the data dir (`~/.sagebox`). When stdin is not a TTY, every passphrase/value prompt reads one line from stdin in order, e.g. `printf 'pw\nvalue\n' | sgb set gh` (passphrase first, then value). `tests/cli.rs` drives the binary this way against a temp home; the daemon is auto-spawned by the first `exec`/`unlock`, and `sbx_in` sets the cwd so `.sagebox` resolution can be tested.

Flow: admin commands edit the vault file directly with the passphrase (never via the daemon). The daemon is not a service: the first `exec`/`unlock` auto-spawns it, and it exits (wiping the DEK) when the session ends. Each `exec` re-reads the vault, returns the pinned argv + env, and the client clears CLOEXEC on that socket before `execve` so the MCP server inherits it as a *lease*; the daemon sees EOF when the process dies. Namespaces isolate projects: each has its own vault/passphrase/daemon/audit log under `~/.sagebox/ns/<name>/` (default = `~/.sagebox/` itself), chosen by `--ns` > `SAGEBOX_NS` > nearest `.sagebox` file (`namespace = "acme"`) > `default` (`src/namespace.rs`); the auto-spawned daemon gets its namespace via `--ns`. `sgb import-env` / `sgb env` (`src/envfile.rs`) move literal secrets from a project's `.envrc` into a per-project namespace and replace them with `eval "$(sgb env)"`; `sgb env` never uses the daemon session and asks for user presence every time, and refuses to print to a TTY. `sgb mcp add` (`src/mcp.rs`) creates the profile (prompting for missing secrets) and shells out to `claude mcp add`; its test puts a fake `claude` on PATH. `sgb import` (`src/import.rs`) migrates plaintext `env` secrets out of an `mcpServers` JSON config into the vault and rewrites entries to `sgb exec <server>`; it is a dry run unless `--apply`, classifies locally, and never prints values. When a `.sagebox` file picks a named namespace, the client sends that project dir and the daemon requires it in the vault's `trusted` set (`sgb trust`, needs that namespace's passphrase). Session ends 30s after the last lease, or at the 8h cap / `lock`. The daemon also exits on system sleep (wall clock outruns `Instant`) and macOS screen lock (`src/macos.rs`, CoreGraphics FFI). Debug with `SAGEBOX_DEBUG=1` (daemon writes `<ns dir>/debug.log`, client writes stderr); `SAGEBOX_NO_AUTOLOCK=1` disables sleep/screen-lock locking (tests set it to avoid flakes). Touch ID (`src/touchid.rs`, `src/macos.rs`): a `secure_enclave` vault slot whose KEK comes from ECDH with a user-presence-bound Secure Enclave key; restore the key by passing the blob as the `toid` attribute (passing it as key data silently creates a *new* key). The client unlocks it and sends the DEK via `UnlockKey`; `cargo test se_roundtrip -- --ignored` exercises it and needs a human to answer the system dialog. Locked `exec` asks via a GUI dialog; set `SAGEBOX_NO_GUI=1` in tests (the `sbx` helper does) so no dialog pops up. An auto-spawned daemon from a failed test exits on its own within 2–10 minutes.

## Constraints

- Ship as one lightweight binary. The release profile in `Cargo.toml` (opt-level "z", LTO, strip, panic=abort) exists for this; keep dependencies few and justify each.
- Never hand-roll cryptography. Use vetted RustCrypto crates for AEAD/KDF.
- Hold secret values in `secrecy`/`zeroize` types so they are wiped on drop; never log or `Debug`-print them.
- Local IPC only (Unix domain socket 0600; Windows later via named pipe). Do not open network ports.
- Target macOS and Linux now; Windows must keep compiling. Isolate platform code behind `#[cfg(...)]`, and never use `std::os::unix` unguarded.
- Vault slots: every slot derives a 32-byte KEK and unwraps the same DEK. Unknown slot kinds must be preserved verbatim when re-sealing.
- New source files start with a one-line Korean comment describing their role.
- Commit messages must follow `<type>(<scope>): <설명>` (feat, fix, docs, chore, refactor, test, …); a git hook rejects other formats.
