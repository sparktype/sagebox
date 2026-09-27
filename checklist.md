# secretbox 체크리스트

## 1단계 — 볼트 (암호화 저장소)
- [x] `src/vault.rs` 파일 형식 인코딩/디코딩 → verify: 라운드트립 테스트
- [x] 잘못된 패스프레이즈·변조된 헤더·변조된 본문 거부 → verify: 실패 테스트
- [x] 원자적 저장 (tmp + rename, 0600) → verify: 테스트
- [x] 봉투 형식 SBX2 (DEK + 패스프레이즈 슬롯, 모르는 슬롯 보존) → verify: 테스트 7개, linux·windows `cargo check`

## 2단계 — 관리 CLI
- [x] `init`, `set <name>`(tty 무에코 입력), `rm <name>`, `list`
- [x] `profile add <name> --env ENV=secret ... -- <argv>`, `profile rm`
- [x] verify: 임시 HOME에서 수동 실행 + `tests/cli.rs`

## 3단계 — 데몬과 exec
- [x] `daemon`: 소켓 0600, `getpeereid` UID 확인, 세션 키 보관, TTL
- [x] `unlock` / `lock` / `status`
- [x] `exec <profile>`: 요청 → argv/env 수신 → execve
- [x] 감사 로그 (JSON Lines)
- [x] verify: `secretbox exec` 로 `env` 를 고정한 테스트 프로필이 값을 받는지, 잠금 상태에서 거부되는지

- [ ] Linux 실기 검증 (`SO_PEERCRED` 경로는 컴파일·clippy만 통과, 실행은 안 해 봄)
- [ ] 데몬 자동 시작 (launchd / systemd user unit)

## 3.5단계 — secretctl 흡수
- [x] 환경변수 이름·예약 변수·NUL 값·패스프레이즈 길이 검증
- [x] 비밀 만료일 (`set --expires`, exec 거부, list 표시)
- [x] 감사 로그 MAC 체인 + `audit verify`

## 4단계 — 하드웨어 슬롯 (순차)
- [ ] 스파이크: 서명되지 않은 CLI에서 Secure Enclave 키 생성·ECDH·Touch ID가 동작하는가 → verify: 최소 실행 파일로 확인
- [ ] `secure_enclave` 슬롯 (macOS, `cfg(target_os = "macos")`)
- [ ] FIDO2 `hmac-secret` 또는 TPM2 슬롯 검토 (Linux)

## 나중에 — Windows
- [ ] named pipe IPC + 클라이언트 SID 확인
- [ ] `exec`: 자식 실행 + stdio 상속 + 종료 코드 전달
