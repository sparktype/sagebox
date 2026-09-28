# sagevault 체크리스트

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
- [x] verify: `sgv exec` 로 `env` 를 고정한 테스트 프로필이 값을 받는지, 잠금 상태에서 거부되는지

- [ ] Linux 실기 검증 (`SO_PEERCRED` 경로는 컴파일·clippy만 통과, 실행은 안 해 봄)

## 3.5단계 — secretctl 흡수
- [x] 환경변수 이름·예약 변수·NUL 값·패스프레이즈 길이 검증
- [x] 비밀 만료일 (`set --expires`, exec 거부, list 표시)
- [x] 감사 로그 MAC 체인 + `audit verify`

## 3.6단계 — 세션 = 에이전트 수명 (임대 방식)
- [x] IPC를 길이 접두 방식으로 바꾸기 (exec 연결을 임대로 열어 둬야 하므로 EOF framing 불가)
- [x] 데몬: 연결별 스레드, 임대 계수, 종료 정책(임대 0 + 30초 / 첫 임대 대기 10분 / 잠김 2분 / 절대 8시간), 종료 시 DEK 삭제·소켓 제거·프로세스 종료
- [x] 클라이언트: 데몬 자동 기동(double fork + setsid), 임대 fd의 CLOEXEC 해제 후 execve
- [x] 잠김 상태 exec → GUI 프롬프트(macOS osascript, Linux zenity/kdialog/pinentry), `SAGEVAULT_NO_GUI`
- [x] `lock` → 데몬 종료, `status`에 활성 임대 수 표시
- [x] verify: 종료 정책 단위 테스트, 통합 테스트(자동 기동, 임대 증감, lock 시 소켓 제거)
- [x] ~~데몬 자동 시작 (launchd / systemd)~~ → 임대 방식으로 대체

- [ ] GUI 프롬프트 실기 확인 (macOS 대화상자 입력, Linux zenity/kdialog/pinentry). 자동 테스트는 `SAGEVAULT_NO_GUI`로 끔

## 3.7단계 — 프로젝트별 네임스페이스 (보안 격리)
- [x] 네임스페이스마다 볼트·패스프레이즈·데몬(소켓)·감사 로그를 분리한다. default는 기존 `~/.sagevault`, 이름 있는 것은 `~/.sagevault/ns/<name>/`
- [x] 결정 순서: `--ns` > `SAGEVAULT_NS` > 상위 탐색한 `.sagevault` 파일(`namespace = "acme"`) > default
- [x] 이름 검증 `[a-z0-9][a-z0-9_-]{0,31}` (경로 탈출 방지, 소켓 경로 길이 제한)
- [x] 자동 기동 데몬에 네임스페이스 전달, GUI 프롬프트·status에 네임스페이스와 프로젝트 표시
- [x] `sgv ns`: 현재 네임스페이스와 그 출처, 존재하는 목록
- [x] verify: 결정 순서·파싱·검증 단위 테스트, 두 네임스페이스 격리 통합 테스트

- [x] 프로젝트 신뢰 등록 (`trust`/`untrust`, 볼트에 저장, 데몬이 검사)

## 3.8단계 — 평문 MCP 설정 가져오기 (`sgv import`)
- [x] `src/import.rs`: `mcpServers` JSON 파싱, env 변수 분류(값 모양 + 이름 규칙, 애매하면 비밀), 명령 절대경로 고정
- [x] 기본은 미리보기, `--apply`로 볼트(비밀·프로필)와 설정 파일을 원자적으로 바꾼다. `--keep VAR`, 값은 절대 출력하지 않는다
- [x] 이미 sgv로 관리 중인 서버와 비밀이 없는 서버는 건너뛴다. 이름 충돌은 쓰기 전에 전부 검사한다
- [x] verify: 분류 단위 테스트, 미리보기→적용→exec 통합 테스트, 적용 후 설정 파일에 평문 없음
- [ ] (보류, 2026-09-28 사용자 결정) `--assist`: 애매한 변수 **이름만** Jev로 판단. 재개 시 결정할 것: HTTP는 시스템 curl + stdin 헤더, API 키는 볼트에 보관
- [ ] (보류) `sgv trust --scan`: 저장소 지시 파일을 Jev로 검사(옵트인, 경고만)

## 3.9단계 — Mac 편의 기능 (사용자 결정 순서)
- [x] 잠자기 감지(벽시계 − 단조 시계 차이 > 30초)와 화면 잠금 감지(macOS `CGSSessionScreenIsLocked`) 시 데몬 종료 → verify: 잠자기 판정 단위 테스트, 세션 조회 실기(잠금 해제 상태에서 키 없음 확인)
  - [ ] 실제로 화면을 잠갔을 때 데몬이 종료되는지 사용자 확인 (`SAGEVAULT_DEBUG=1`로 debug.log의 `end … screen locked`)
- [x] 개발·디버깅 환경변수 `SAGEVAULT_DEBUG`, `SAGEVAULT_NO_AUTOLOCK`
- [x] Touch ID 스파이크: Secure Enclave 키(C Security API, `toid` 블롭 파일, `userPresence`)가 서명 없는 CLI·에이전트 맥락에서 동작. 키체인 방식은 기각(생체 항목 -34018, 빌드마다 ACL 문제)
- [x] `secure_enclave` 슬롯 구현
  - [x] vault: 슬롯 추가·제거·해제 API, 공유 비밀 → KEK 유도(BLAKE2b-MAC) → verify: 가짜 KEK 단위 테스트
  - [x] `src/macos.rs`: SE 키 생성(`toid` 블롭), 소프트웨어 임시 키 ECDH, SE 개인키 ECDH(대화상자) FFI
  - [x] `sgv touchid enable|disable|status`, `unlock`·잠긴 `exec`에서 SE 우선 → 실패·취소 시 패스프레이즈, `unlock --passphrase`
  - [x] 데몬 `UnlockKey { dek }` 요청(클라이언트가 푼 DEK를 검증 후 세션 시작)
  - [x] verify: 사용자와 실기(enable → unlock 대화상자·설명 문구 → exec → 취소 시 패스프레이즈로 대체)
- [ ] exec 알림 (알림 센터, 세션당 프로필별 1회)
- [x] `sgv mcp add <서버> [--env VAR=비밀]... [--scope local|user|project] -- <명령> [인자]` → 명령 절대경로 고정, 없는 비밀은 그 자리에서 입력, 프로필 생성, `claude mcp add` 실행(없으면 수동 안내), 설정 JSON 조각 출력 → verify: 가짜 claude로 인자 검증하는 통합 테스트
- [ ] `.envrc` 가져오기 + direnv 연동
  - [x] vault: `shell_env`(셸로 내보낼 VAR → 비밀) 필드, 기존 볼트 호환
  - [x] `src/envfile.rs`: `.envrc`/`.env` 파싱(`export K=V`, `K=V`, 따옴표), 리터럴이 아닌 값(`$`, 백틱)은 제외 → verify: 파싱 단위 테스트
  - [x] `sgv import-env <파일> [--keep VAR]... [--apply]`: 프로젝트 네임스페이스(디렉터리 이름 또는 기존 .sagevault), 없으면 init + Touch ID, `.sagevault`·trust, 비밀 이동, 첫 비밀 줄 자리에 `eval "$(sgv env)"`, git 추적 경고, direnv allow 안내
  - [x] `sgv env [--print]`: 매번 SE(없으면 GUI 패스프레이즈) 확인, 데몬 세션 안 씀, trust·만료 검사, stdout이 터미널이면 거부
  - [ ] verify: 통합 테스트(미리보기 → 적용 → sgv env 출력), 실제 프로젝트는 사용자와
- [ ] `sgv copy <비밀>` (클립보드, 30초 후 지움)

## 4단계 — 하드웨어 슬롯 (순차)
- [x] 스파이크: 서명되지 않은 CLI에서 Secure Enclave 키 생성·ECDH·사용자 확인 → 가능 (3.9단계 참고)
- [ ] `secure_enclave` 슬롯 (macOS, `cfg(target_os = "macos")`)
- [ ] FIDO2 `hmac-secret` 또는 TPM2 슬롯 검토 (Linux)

## 나중에 — Windows
- [ ] named pipe IPC + 클라이언트 SID 확인
- [ ] `exec`: 자식 실행 + stdio 상속 + 종료 코드 전달
