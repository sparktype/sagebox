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

## 3.5단계 — secretctl 흡수
- [x] 환경변수 이름·예약 변수·NUL 값·패스프레이즈 길이 검증
- [x] 비밀 만료일 (`set --expires`, exec 거부, list 표시)
- [x] 감사 로그 MAC 체인 + `audit verify`

## 3.6단계 — 세션 = 에이전트 수명 (임대 방식)
- [x] IPC를 길이 접두 방식으로 바꾸기 (exec 연결을 임대로 열어 둬야 하므로 EOF framing 불가)
- [x] 데몬: 연결별 스레드, 임대 계수, 종료 정책(임대 0 + 30초 / 첫 임대 대기 10분 / 잠김 2분 / 절대 8시간), 종료 시 DEK 삭제·소켓 제거·프로세스 종료
- [x] 클라이언트: 데몬 자동 기동(double fork + setsid), 임대 fd의 CLOEXEC 해제 후 execve
- [x] 잠김 상태 exec → GUI 프롬프트(macOS osascript, Linux zenity/kdialog/pinentry), `SECRETBOX_NO_GUI`
- [x] `lock` → 데몬 종료, `status`에 활성 임대 수 표시
- [x] verify: 종료 정책 단위 테스트, 통합 테스트(자동 기동, 임대 증감, lock 시 소켓 제거)
- [x] ~~데몬 자동 시작 (launchd / systemd)~~ → 임대 방식으로 대체

- [ ] GUI 프롬프트 실기 확인 (macOS 대화상자 입력, Linux zenity/kdialog/pinentry). 자동 테스트는 `SECRETBOX_NO_GUI`로 끔

## 4단계 — 하드웨어 슬롯 (순차)
- [ ] 스파이크: 서명되지 않은 CLI에서 Secure Enclave 키 생성·ECDH·Touch ID가 동작하는가 → verify: 최소 실행 파일로 확인
- [ ] `secure_enclave` 슬롯 (macOS, `cfg(target_os = "macos")`)
- [ ] FIDO2 `hmac-secret` 또는 TPM2 슬롯 검토 (Linux)

## 나중에 — Windows
- [ ] named pipe IPC + 클라이언트 SID 확인
- [ ] `exec`: 자식 실행 + stdio 상속 + 종료 코드 전달
