# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

secretbox is a personal secret-management daemon for AI agents: agents fetch passwords/API keys on demand over a local, authenticated channel and use them for MCP servers or skills. Requirements and design decisions live in `SPEC.md` — read it before implementing a feature, and update it (move items from "설계 초안"/"열린 질문" to "확정된 요구사항") when a decision is made.

Status: vault file format (`src/vault.rs`, envelope encryption: random DEK + key slots) is done; CLI and daemon are not. Progress is tracked in `checklist.md`, decision rationale in `context-notes.md`.

## Commands

```sh
cargo build                      # debug build
cargo build --release            # single small binary at target/release/secretbox
cargo test                       # all tests
cargo test <name>                # tests whose path contains <name>
cargo clippy --all-targets -- -D warnings
cargo fmt

# 크로스플랫폼 컴파일 확인 (타깃은 rustup target add로 설치)
cargo check --all-targets --target x86_64-unknown-linux-gnu
cargo check --all-targets --target x86_64-pc-windows-msvc
```

## Constraints

- Ship as one lightweight binary. The release profile in `Cargo.toml` (opt-level "z", LTO, strip, panic=abort) exists for this; keep dependencies few and justify each.
- Never hand-roll cryptography. Use vetted RustCrypto crates for AEAD/KDF.
- Hold secret values in `secrecy`/`zeroize` types so they are wiped on drop; never log or `Debug`-print them.
- Local IPC only (Unix domain socket 0600; Windows later via named pipe). Do not open network ports.
- Target macOS and Linux now; Windows must keep compiling. Isolate platform code behind `#[cfg(...)]`, and never use `std::os::unix` unguarded.
- Vault slots: every slot derives a 32-byte KEK and unwraps the same DEK. Unknown slot kinds must be preserved verbatim when re-sealing.
- New source files start with a one-line Korean comment describing their role.
- Commit messages must follow `<type>(<scope>): <설명>` (feat, fix, docs, chore, refactor, test, …); a git hook rejects other formats.
