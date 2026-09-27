# secretbox 체크리스트

## 1단계 — 볼트 (암호화 저장소)
- [ ] `src/vault.rs` 파일 형식 인코딩/디코딩 → verify: 라운드트립 테스트
- [ ] 잘못된 패스프레이즈·변조된 헤더·변조된 본문 거부 → verify: 실패 테스트
- [ ] 원자적 저장 (tmp + rename, 0600) → verify: 테스트

## 2단계 — 관리 CLI
- [ ] `init`, `set <name>`(tty 무에코 입력), `rm <name>`, `list`
- [ ] `profile add <name> --env ENV=secret ... -- <argv>`, `profile rm`
- [ ] verify: 임시 HOME에서 수동 실행

## 3단계 — 데몬과 exec
- [ ] `daemon`: 소켓 0600, `getpeereid` UID 확인, 세션 키 보관, TTL
- [ ] `unlock` / `lock` / `status`
- [ ] `exec <profile>`: 요청 → argv/env 수신 → execve
- [ ] 감사 로그 (JSON Lines)
- [ ] verify: `secretbox exec` 로 `env` 를 고정한 테스트 프로필이 값을 받는지, 잠금 상태에서 거부되는지
