# sagebox 스펙

에이전트(Claude Code, Codex 등)가 MCP 서버나 스킬을 실행할 때 필요한 비밀(비밀번호, API 키, 토큰)을 필요한 순간에만 받아가도록 하는 개인용 로컬 데몬.

## 확정된 요구사항

- 단일 바이너리. 런타임 의존성 없음 (Rust, release 프로필에서 LTO·strip).
- 비밀은 디스크에 항상 암호화된 상태로 저장.
- 에이전트와의 통신은 로컬 전용이며 인증된 호출자만 비밀을 받는다.
- 비밀 값은 사용 후 메모리에서 지운다 (zeroize).
- **전달 방식은 직전 실행 주입.** 에이전트 설정에는 `sagebox exec <profile>`만 적는다. 비밀은 실행되는 프로세스의 환경변수로만 들어가고 에이전트 대화·설정 파일에는 남지 않는다.
- **세션 = 에이전트 수명.** 데몬은 상시 서비스가 아니다. 첫 `exec` 또는 `unlock` 때 자동으로 뜨고(double fork + setsid), 세션이 끝나면 DEK를 지우고 소켓을 치운 뒤 스스로 종료한다.
  - 잠긴 상태의 `exec`(터미널 없음)는 GUI 대화상자로 패스프레이즈를 묻는다. 요청한 부모 프로세스 이름을 보여 주며 최대 3번 묻는다. macOS는 `osascript`, Linux는 `zenity` → `kdialog` → `pinentry` 순서다. 쓸 수 있는 도구가 없거나 `SAGEBOX_NO_GUI`가 설정돼 있으면 `sagebox unlock`을 안내하고 실패한다. 터미널의 `sagebox unlock`도 계속 쓸 수 있다.
  - **임대.** `exec` 연결은 응답 뒤에도 열어 둔다. 클라이언트는 그 소켓의 CLOEXEC를 풀고 execve하므로 MCP 서버(와 그 자식들)가 소켓을 물려받는다. 프로세스가 모두 사라지면 커널이 소켓을 닫고, 데몬은 EOF로 임대 종료를 안다.
  - 종료 조건은 다음 중 먼저 오는 쪽이다. 임대 0개가 된 뒤 30초, 터미널 unlock 후 첫 임대 없이 10분, 잠긴 채 요청 없이 2분, 잠금 해제 후 8시간(임대가 남아 있어도), 그리고 `lock`이다. 시간은 벽시계로 재고(단조 시계는 절전 중 멈춤) 시계가 뒤로 가면 종료한다. 확인 주기는 5초다.
- **프로필별 접근 정책.** 프로필은 실행할 명령(argv)과 주입할 `ENV ← 비밀이름` 매핑을 고정한다. 명령은 절대경로여야 한다. 환경변수 이름은 POSIX 형식이어야 하고, `PATH`·`HOME` 등 예약 변수와 `LD_*`·`DYLD_*` 로더 변수는 덮어쓸 수 없다.
- **입력 검증.** 패스프레이즈는 8자 이상이어야 한다(볼트 파일은 같은 UID면 오프라인 대입 공격이 가능하다). 비밀 값에는 NUL 바이트가 들어갈 수 없다.
- **프로젝트별 네임스페이스(보안 격리).** 네임스페이스마다 볼트·패스프레이즈·데몬(소켓)·감사 로그가 따로다. 한 프로젝트를 풀어도 다른 네임스페이스는 잠긴 채로 남는다.
  - 결정 순서는 `--ns <name>`, `SAGEBOX_NS`, 가장 가까운 상위 디렉터리의 `.sagebox` 파일(`namespace = "acme"`), `default` 순이다. `sagebox ns`로 현재 네임스페이스와 그 출처를 볼 수 있다.
  - 이름은 `[a-z0-9][a-z0-9_-]`, 최대 32자다(경로 탈출 방지, 소켓 경로 길이 제한).
  - 경로는 default가 `~/.sagebox/`(기존 그대로), 이름 있는 것은 `~/.sagebox/ns/<name>/`이다.
  - 잠긴 네임스페이스의 GUI 프롬프트에는 네임스페이스, 프로젝트 경로, 요청 프로세스를 표시한다.
  - **프로젝트 신뢰 등록.** `.sagebox` 파일이 이름 있는 네임스페이스를 골랐다면, 그 파일이 있는 디렉터리(정규화 경로)가 해당 네임스페이스 볼트의 `trusted` 목록에 있어야 `exec`가 허용된다. 검사는 데몬이 볼트를 열어서 하므로, 이미 풀린 네임스페이스라도 등록되지 않은 저장소의 요청은 거부된다.
    - `sagebox trust`는 그 네임스페이스의 패스프레이즈가 있어야 한다. 저장소 지시를 따른 에이전트가 스스로 등록하지 못하게 하기 위해서다. `untrust [dir]`로 해제하고, `list`로 목록을 본다.
    - 저장소가 `.sagebox`를 다른 네임스페이스로 바꾸면, 그쪽 목록에는 해당 디렉터리가 없으므로 다시 거부된다.
    - `--ns`와 `SAGEBOX_NS`는 사용자가 직접 쓴 설정이라 검사하지 않는다. `default`도 전역 네임스페이스라 검사하지 않는다. 프로젝트 `.mcp.json`에 `--ns personal`이 들어 있는 경우는 에이전트의 MCP 서버 승인 화면에 드러나는 것에 기댄다.
- **프로젝트 환경 파일 가져오기와 direnv 연동.**
  - `sagebox import-env <.envrc|.env> [--keep VAR]... [--apply]`는 리터럴 할당(`export K=V`, `K=V`, 따옴표)만 본다. 셸 계산 값(`$`, 백틱, 공백 등)과 direnv 함수 줄은 그대로 둔다.
  - 비밀은 프로젝트 네임스페이스로 옮긴다. 네임스페이스는 파일이 있는 디렉터리의 `.sagebox`를 따르고, 없으면 디렉터리 이름에서 만든다. 새 네임스페이스는 새 패스프레이즈를 받고 macOS에서는 Touch ID 슬롯도 켠다. `.sagebox`를 만들고 프로젝트를 신뢰 등록하며, 볼트의 `shell_env`(VAR → 비밀)에 기록한다.
  - `.envrc`에서는 비밀 줄만 빼고 나머지는 유지한다(2026-09-28부터 `eval "$(sagebox env)"` 줄은 넣지 않는다). 비밀은 `sagebox run -- <명령>`이 넣고, `sagebox env`는 수동용으로만 남는다. `direnv allow`는 대신 실행하지 않는다. git 추적 파일이면 기록에 남은 평문을 교체하라고 경고한다.
  - `sagebox env [--print]`는 **매번** 사용자 확인(SE 슬롯의 Touch ID/로그인 암호, 없으면 GUI 패스프레이즈)을 거쳐 `export K='V'`를 출력한다. 데몬 세션은 쓰지 않는다. 신뢰 등록과 만료일 검사를 적용하고, stdout이 터미널이면 `--print` 없이는 거부한다.
- **MCP 등록 도우미.** `sagebox mcp add <서버> [--env VAR=비밀]... [--scope local|user|project] -- <명령> [인자]`는 한 번에 세 가지를 한다. 명령을 지금의 PATH에서 절대경로로 고정하고, 패스프레이즈 한 번으로 프로필을 만들며(볼트에 없는 비밀은 그 자리에서 입력), `claude mcp add -s <범위> <서버> -- <sagebox> [--ns <이름>] exec <서버>`로 Claude Code에 등록한다. 범위 기본값은 `user`다(개인 자격 증명은 보통 모든 프로젝트에서 쓰기 때문이다). `claude`가 없거나 실패하면 이유를 알리고, 다른 MCP 클라이언트용 JSON 조각은 항상 출력한다.
- **sagebox 자체 MCP 서버.** `sagebox mcp serve`는 stdio MCP 서버로 `status`(잠금 상태·임대 수)와 `list`(비밀 이름·만료일, 프로필의 환경변수→비밀 이름·명령) 도구만 제공한다. 비밀 값은 어떤 도구도 돌려주지 않는다. 데몬은 띄우지 않고 이미 풀린 세션에 `List` 요청으로 묻는다. 잠겨 있으면 `sagebox unlock`을 안내하고, 조회는 감사 로그에 `list`로 남는다. `.sagebox`로 정해진 네임스페이스는 exec와 같은 trust 검사를 한다.
- **`sagebox run -- <명령>`으로 .envrc 대체.** 프로젝트 네임스페이스의 `shell_env`(import-env가 채움)를 그 명령에만 넣고 execve한다. 셸에는 값이 남지 않고 커밋될 파일도 없다. **sagebox MCP 서버(`sagebox mcp serve`)가 떠 있을 때만** 된다. serve는 시작하면 데몬에 `Attach` 임대를 잡고(잠긴 상태여도, 데몬이 없으면 띄움), 데몬이 끝나면 5초 뒤 다시 잡는다. 데몬은 `Run`을 받으면 Attach 임대가 없으면 잠금 해제를 묻기 전에 거부하고, 잠겨 있으면 클라이언트가 Touch ID(또는 GUI 패스프레이즈)로 푼다. Attach 임대도 exec 임대처럼 세션을 유지하므로 Claude Code가 떠 있는 동안 풀린 상태가 이어지고, 끝나면 30초 뒤 잠긴다. 실행은 감사 로그에 `run`(비밀 이름)으로 남는다.
- **셸 훅.** `eval "$(sagebox zsh)"`(또는 `bash`)를 셸 설정에 넣으면 디렉터리에 들어갈 때 `.envrc`/`.env`를 import-env와 같은 분류기로 검사한다. 평문 비밀이 있으면 변수 이름과 이유만 보여 주고 `[y/N]`로 묻는다. y면 `import-env --apply`와 같이 정리하고, 거절하면 파일은 그대로 두고 그 셸에서는 그 디렉터리를 다시 묻지 않는다. zsh는 `chpwd_functions` 맨 앞에 들어가 direnv보다 먼저 돈다. bash는 `PROMPT_COMMAND` 앞에 붙으므로 `direnv hook bash` 줄 뒤에 둬야 한다.
- **평문 MCP 설정 가져오기.** `sagebox import <mcp.json> [--keep VAR]... [--apply]`는 `mcpServers` 형식(Claude Code `.mcp.json`, Claude Desktop, Cursor)의 `env` 평문 비밀을 볼트로 옮긴다.
  - 비밀은 `<서버>.<변수>`로 저장하고, 서버 이름과 같은 프로필을 만든다. 명령은 가져올 때의 PATH에서 절대경로로 고정한다. 설정은 `command: sagebox`, `args: [--ns <이름>,] exec <서버>`로 바꿔 쓴다. 비밀이 아닌 변수는 설정에 남긴다.
  - 분류는 로컬 규칙이다. 값 모양(토큰 접두어, 비밀번호가 든 URL, 웹훅 URL)과 변수 이름을 본다. 애매하면 비밀로 취급하고, `--keep`으로 남길 수 있다. 값은 어떤 출력에도 나오지 않는다.
  - 기본은 미리보기이고 `--apply`에서만 쓴다. 이름 충돌은 쓰기 전에 모두 검사한다. 파일 권한은 유지한다. 평문 백업은 만들지 않고 토큰 교체를 안내한다. 이미 sagebox로 관리 중인 서버는 건너뛴다.
- **잠자기·화면 잠금 시 자동 잠금.** 데몬은 5초마다 두 가지를 확인하고, 해당하면 DEK를 지우고 종료한다.
  - 잠자기: 벽시계가 단조 시계(`Instant`)보다 30초 넘게 더 흘렀으면 그사이 시스템이 잠들었던 것으로 본다. 단조 시계는 잠자기 중 멈추므로, 단순한 스케줄링 지연과 구분된다.
  - 화면 잠금(macOS): CoreGraphics 세션 정보의 `CGSSessionScreenIsLocked`를 본다. GUI 세션 밖(SSH)이라 알 수 없으면 무시한다.
  - 이미 떠 있는 MCP 서버는 환경변수를 가지고 있으므로 계속 동작한다. 새 `exec`는 다시 잠금 해제가 필요하다.
- **개발·디버깅용 환경변수.** 자동 기동된 데몬은 띄운 클라이언트의 환경을 물려받는다.
  - `SAGEBOX_DEBUG=1`: 데몬은 `<네임스페이스 디렉터리>/debug.log`(0600)에, 클라이언트는 stderr에 판단 과정(요청·결과·임대·종료 이유·데몬 기동·GUI 전환)을 남긴다. 비밀 값과 패스프레이즈는 기록하지 않는다.
  - `SAGEBOX_NO_AUTOLOCK=1`: 잠자기·화면 잠금 자동 잠금을 끈다.
  - `SAGEBOX_NO_GUI=1`: GUI 프롬프트를 띄우지 않는다.
- **Touch ID 잠금 해제(macOS).** `sagebox touchid enable|disable|status`. `secure_enclave` 슬롯을 추가·제거한다(추가·제거에는 패스프레이즈가 필요하다).
  - 슬롯 파라미터는 `{blob, epk}`다. `blob`은 SE 키의 `toid`(이 Mac의 하드웨어만 풀 수 있는 암호화된 키)이고, `epk`는 추가할 때 만든 소프트웨어 임시 공개키다. KEK는 BLAKE2b-MAC(키=ECDH 공유 비밀, persona `sbx-slot-kek`, 입력=`epk`)이다.
  - 풀 때는 `SecKeyCreateWithData(빈 데이터, {EC, private, tkid=SE, toid=blob, 사용 설명 문구})`로 키를 되살리고 `epk`와 ECDH한다. SE 키는 `userPresence`로 묶여 있어 이때 시스템 대화상자(Touch ID → Watch → 로그인 암호)가 뜬다.
  - `sagebox unlock`과 잠긴 `exec`는 SE 슬롯을 먼저 시도하고, 취소·실패하면 패스프레이즈(터미널 또는 osascript)로 넘어간다. `unlock --passphrase`는 SE를 건너뛴다. `SAGEBOX_NO_GUI`면 SE도 건너뛴다.
  - SE 해제는 대화상자 맥락이 있는 클라이언트가 한다. 푼 DEK는 `UnlockKey` 요청으로 데몬에 넘기고, 데몬은 볼트를 열어 검증한 뒤 세션을 시작한다. 감사 로그에는 해제 수단(`passphrase`/`secure_enclave`)을 남긴다.
- **감사 로그.** `unlock`·`lock`·`exec` 요청(허용/거부)과 다른 UID의 접속을 `audit.log`(JSON Lines, 0600)에 기록한다. 항목은 시각, 요청 pid, 프로필, 결과, 비밀 이름이다. 비밀 값은 기록하지 않는다. 기록에 실패하면 `exec`를 거부한다.
- **감사 로그 MAC 체인.** 데몬은 첫 `unlock`에서 DEK로부터 감사 키를 유도한다(BLAKE2b-MAC, persona `sbx-audit-key`). 이 키로는 볼트를 열 수 없고, 데몬이 종료될 때까지 보관한다. 이후 각 줄에 `seq`, `prev`(이전 줄의 mac), `mac`을 붙인다. `sagebox audit verify`는 패스프레이즈로 같은 키를 얻어 수정·위조, 중간 삭제, 순번 건너뜀을 찾는다. 첫 unlock 전의 줄은 MAC 없이 기록되고 "unauthenticated"로 따로 센다. 끝부분 잘라내기와 파일 전체 삭제는 탐지하지 못한다.
- **비밀 만료일.** `set <name> --expires YYYY-MM-DD`. 그 날짜의 00:00 UTC부터 해당 비밀을 쓰는 `exec`를 거부한다. `--expires` 없이 `set`하면 만료일을 지운다. 볼트의 `expires` 맵은 선택 필드라 기존 볼트와 호환된다.
- **크로스플랫폼.** macOS·Linux를 먼저 지원한다. Windows는 구조만 열어 둔다(IPC는 named pipe, `exec`는 자식 실행 + stdio 상속). 플랫폼 전용 코드는 `cfg`로 격리한다.
- **봉투 암호화 + 키 슬롯.** 볼트 본문은 무작위 DEK로 암호화한다. 각 슬롯은 DEK를 서로 다른 방법으로 감싼다. 패스프레이즈 슬롯은 항상 존재하며 복구 경로 역할을 한다.
- **하드웨어 슬롯은 순차 도입.** macOS Secure Enclave부터 시작한다. 2026-09-28 스파이크에서 서명 없는 CLI(에이전트가 띄운 프로세스 포함)로도 동작함을 확인했다. 키는 `userPresence`로 묶는다(Touch ID, Watch, 덮개를 닫았을 때는 로그인 암호). 키체인이 아니라 암호화된 SE 블롭(`toid`)을 슬롯에 둔다. 이후 FIDO2 `hmac-secret`, TPM2를 검토한다.

## 위협 모델

막는 것
- 디스크에 평문 비밀이 남는 것 (dotfile, MCP 설정, `.env`).
- 비밀이 에이전트 컨텍스트나 대화 기록에 들어가는 것.
- 잠긴 상태에서 비밀에 접근하는 것.
- 다른 UID 사용자의 접근 (소켓 0600 + `getpeereid`).
- 정책 변조. 프로필은 암호화된 볼트 안에 있어서 패스프레이즈 없이는 바꿀 수 없다.

막지 못하는 것 (같은 UID의 셸 권한 에이전트)
- 실행 중인 자식 프로세스의 환경변수는 같은 UID면 읽을 수 있다 (macOS `KERN_PROCARGS2`).
- 잠금 해제 상태에서는 프로필에 고정된 명령을 누구나 실행할 수 있다. 다만 명령 자체를 바꿀 수는 없다.
- 결론적으로 sagebox는 비밀 위생(평문 제거·노출 최소화·감사)을 위한 도구이며, 악의적인 동일 사용자 프로세스를 격리하지는 않는다.

## 구조

```
sagebox exec github ──(Unix socket, JSON 한 줄)──▶ daemon
                                                     │ 잠금 해제됨? 프로필 존재?
                                                     │ 볼트 파일을 세션 키로 복호화
                                                     │ 감사 로그 기록
        ◀── {argv, env} ────────────────────────────┘
execve(argv, env)   ← 클라이언트 프로세스가 MCP 서버로 바뀜 (stdio 그대로)
```

- **daemon**은 세션 키(Argon2id로 유도한 32바이트)만 메모리에 보관한다. `exec` 요청마다 볼트 파일을 새로 읽어 복호화하므로 관리 명령과 동기화할 필요가 없다.
- **관리 명령**(`init`, `set`, `rm`, `profile`)은 데몬을 거치지 않고 패스프레이즈로 볼트 파일을 직접 편집한다. 잠금 해제된 세션이 관리 권한으로 번지지 않는다.
- 볼트 파일 쓰기는 임시 파일에 쓴 뒤 rename한다 (원자적 교체).

## IPC 프로토콜

- 연결 하나에 요청 하나. 메시지는 `길이(u32 LE) + JSON`이며 최대 1 MiB, I/O 타임아웃은 5초다. exec 연결은 임대로 열어 두므로 EOF로 메시지 끝을 알릴 수 없다.
- 데몬은 연결마다 스레드를 둔다(임대 연결이 오래 열려 있기 때문이다).
- 요청: `{"op": "unlock", "passphrase"}` / `lock` / `status` / `{"op": "exec", "profile"}`.
- 응답: `{"result": "ok"}` / `error` / `locked` / `{"result": "status", "unlocked", "leases", "absolute_left_secs"}` / `{"result": "exec", "command", "env"}`.
- 감사 로그 op에 `release`(임대 종료)와 `end`(데몬 종료와 그 이유)가 추가된다.

## 볼트 파일 형식

```
"SBX2" | header_len(u32 LE) | header(JSON) | nonce(24) | body ciphertext+tag
```

- 본문: XChaCha20-Poly1305(DEK), AAD = 앞의 `"SBX2" | header_len | header` 전체. 슬롯이나 파라미터를 바꾸면 본문 인증이 깨진다.
- 헤더: `{"version": 2, "slots": [{"kind", "params", "nonce", "wrapped"}]}`.
  - 모든 슬롯은 어떤 방법으로든 32바이트 KEK를 얻고, `wrapped = XChaCha20-Poly1305(KEK, DEK)`를 푼다. 슬롯마다 다른 것은 KEK를 얻는 방법뿐이다.
  - 모르는 `kind`는 해석하지 않고 그대로 보존한다. 다른 OS에서 추가한 하드웨어 슬롯이 관리 명령 한 번에 지워지지 않게 하기 위해서다.
  - `passphrase` 슬롯: `params = {salt(16), m_cost, t_cost, p_cost}`, KEK = Argon2id. 기본값은 m=64 MiB, t=3, p=1이다. wrap의 AAD는 `kind`와 `params`의 직렬화이므로 파라미터를 낮추는 변조를 막는다.
- 평문: JSON `{"secrets": {이름: 값}, "profiles": {이름: {"command": [...], "env": {ENV: 비밀이름}}}}`.
- 데몬은 세션 동안 DEK만 보관한다. 저장할 때마다 본문 nonce를 새로 뽑고, DEK와 슬롯은 유지한다.

## 기본 경로

- default 네임스페이스는 볼트 `~/.sagebox/vault`, 소켓 `~/.sagebox/sock`, 감사 로그 `~/.sagebox/audit.log`를 쓴다. 이름 있는 네임스페이스는 같은 파일들을 `~/.sagebox/ns/<name>/` 아래에 둔다. 디렉터리 모드는 0700 (Unix). `SAGEBOX_HOME`으로 루트를 바꿀 수 있다.

## 열린 질문


- `mlock`으로 세션 키가 스왑되지 않게 막을지. macOS는 스왑을 기본 암호화하므로 우선순위는 낮다.
