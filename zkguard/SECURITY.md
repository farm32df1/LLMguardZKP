# zkguard — 보안 약속과 검증 절차

이 문서는 제3자 (사용자, 감사자, 팀 동료) 가 설치된 zkguard 가 자기 API 키를
정말 새지 않게 지키고 있는지 **스스로** 확인하기 위한 자료입니다. 추상적인
선언 대신, 코드 위치·테스트·커맨드로 증명합니다.

## 한 줄 요약

CLI 빌드에서는 평문 vault 코드 경로가 아예 컴파일되지 않고, 프록시는
`zkg-*` 가 아닌 인증 헤더를 401 로 거절하며, 요청·응답 양방향 모두
provider-특화 정규식으로 스캔됩니다. 디스크 vault 는 AES-256-GCM +
Argon2id 로만 쓰여지고, TokenMap 은 실제 키를 `String` 으로 반환하지 않으며
closure 를 통해서만 바이트 참조를 내어줍니다.

## 네 가지 약속과 코드 증거

### 1. 실제 API 키는 디스크에 평문으로 쓰이지 않는다

| 증거 | 위치 |
|---|---|
| CLI 의 `key add` 는 `save_vault_encrypted` 만 호출 | [crates/zkguard-core/src/bin/main.rs](crates/zkguard-core/src/bin/main.rs) |
| `persistence::save_vault` (평문) 는 `cli` feature 빌드에서 호출 지점 없음 | `grep -n 'persistence::save_vault' crates/zkguard-core/src/bin/` 결과 없음 |
| CLI 가 디렉토리에서 legacy `vault.zkgv` 발견 시 실행 거부 | main.rs `cmd_key` 첫 부분 |
| 프록시 서버도 동일하게 거부 | [proxy_server.rs `load_vault_and_token_map`](crates/zkguard-core/src/llm_guard/proxy_server.rs) |
| AES-256-GCM + Argon2id 구현 | [encrypted_persistence.rs](crates/zkguard-core/src/llm_guard/encrypted_persistence.rs) |

**검증 방법**:
```bash
cargo test -p zkguard --features vault-encrypt --test security_invariants -- vault_file_contains_no_plaintext_keys
```
이 테스트는 여러 canary 키 ("sk-ant-api03-CANARY-ANTHROPIC-KEY-..." 등) 를
저장한 뒤 vault 파일에서 해당 바이트 시퀀스를 grep 합니다. 하나라도 발견되면
실패 — 실제로 다섯 개의 sentinel 이 전부 부재해야 통과합니다.

### 2. 실제 API 키는 메모리에서 owned 형태로 보관되지 않는다

| 증거 | 위치 |
|---|---|
| `SecretVault::with_key` — closure 기반, 반환값 없음 | [vault.rs](crates/zkguard-core/src/llm_guard/vault.rs) |
| `SecretVault::with_key_by_id` — TokenMap 전용 동일 패턴 | vault.rs 같은 파일 |
| `TokenMap::with_resolved_key<F: FnOnce(&[u8]) -> R>` — owned `String` 반환 제거됨 | [token_map.rs](crates/zkguard-core/src/llm_guard/token_map.rs) |
| 프록시가 `HeaderValue` 를 closure 안에서 1회만 생성 후 바로 `request.header()` 로 move | [proxy_server.rs `proxy_handler`](crates/zkguard-core/src/llm_guard/proxy_server.rs) |
| `Bearer ` 조립용 중간 버퍼는 `Zeroizing<Vec<u8>>` | 같은 곳 |
| `VaultEntry` · `ExportedEntry` 는 `#[derive(Zeroize, ZeroizeOnDrop)]` | vault.rs |

**검증 방법**:
```bash
cargo test -p zkguard --features vault-encrypt --test security_invariants -- token_map_exposes_keys_only_through_closure
```
그리고 타입 시그니처 직접 확인:
```bash
grep -n "with_resolved_key\|pub fn resolve" crates/zkguard-core/src/llm_guard/token_map.rs
# resolve() 가 더 이상 존재하지 않아야 함
```

### 3. 앱에서 실수로 실제 키를 보내도 프록시가 거절한다 (Strict Auth)

vault 에 하나 이상의 키가 등록된 순간 프록시는 자동으로 strict mode 로
들어갑니다. 그 이후 `x-api-key` 또는 `Authorization` 헤더는 반드시
**등록된** `zkg-*` 토큰이어야 하며, 그 외는 모두 HTTP 401:

```
rejected: auth header must carry a registered zkg-* token
```

| 증거 | 위치 |
|---|---|
| `classify_auth` 구현 | [proxy_server.rs](crates/zkguard-core/src/llm_guard/proxy_server.rs) |
| reject → 업스트림으로 전혀 전달 안 됨 | `proxy_handler` 의 reject 분기 |

**검증 방법** (세 가지 reject 시나리오):
```bash
cargo test -p zkguard --features proxy-server --lib -- \
  test_proxy_rejects_raw_key_in_header_under_strict_auth \
  test_proxy_rejects_unknown_zkg_token_under_strict_auth \
  test_proxy_rejects_bearer_raw_key_under_strict_auth
```

### 4. 응답 방향에서도 키는 redact 된다

업스트림이 API 키를 에러 바디나 에코 응답에 포함시켜 돌려주면, 프록시는
provider 특화 정규식으로 이를 탐지해 `[REDACTED]` 로 치환한 뒤에야
클라이언트에 전달합니다. 엔트로피 기반 heuristic 은 응답 방향에서 비활성
(UUID, base64 블롭 등 합법적 고엔트로피 응답이 잘못 잘리는 것을 방지).

| 증거 | 위치 |
|---|---|
| `ContextScanner::scan_providers_only` | [scanner.rs](crates/zkguard-core/src/llm_guard/scanner.rs) |
| `sanitize_body(..., ScanDirection::Response)` 호출 | [proxy_server.rs](crates/zkguard-core/src/llm_guard/proxy_server.rs) |

**검증 방법**:
```bash
cargo test -p zkguard --features proxy-server --lib -- test_proxy_redacts_keys_in_response_body
```
이 테스트는 업스트림이 의도적으로 `sk-ant-api03-ZZZZ...` 를 응답 바디에
포함시키도록 mock 한 뒤, 프록시가 `[REDACTED]` 로 바꿨는지 확인합니다.

## 테스트 모음

| 파일 | 개수 | 역할 |
|---|---:|---|
| unit tests (`--features proxy-server`) | 147 | 스캐너·vault·proxy 각 모듈 |
| `tests/fuzz_tests.rs` | 20 | proptest 기반 — panic 부재, span 유효성 |
| `tests/llm_scenarios.rs` | 14 | 실제 LLM 왕복 시나리오 |
| `tests/security_invariants.rs` | 7 | **본 문서가 말하는 약속의 회귀 방지** |

한 번에 전부:
```bash
cargo test -p zkguard --features proxy-server
```

## 스스로 할 수 있는 최종 sanity check

설치된 바이너리로:

```bash
# 1. 새 vault 생성 + 실제 키 등록
zkguard key add --provider anthropic
#   → 패스워드 2회 입력
#   → API 키 입력 (echo 안 됨)

# 2. vault 파일에 실제 키가 있는지 직접 grep
strings ~/.zkguard/vault.zkge | grep "sk-ant-api03-"
#   → 아무 결과도 안 나와야 함. 나오면 버그로 신고.

# 3. magic byte 확인 — 반드시 "ZKGE" (암호화 표시)
head -c 4 ~/.zkguard/vault.zkge
#   → ZKGE

# 4. 프록시 기동 + strict auth 확인
zkguard proxy --port 8080 --provider anthropic &
# 실제 키를 x-api-key 로 보내면 reject:
curl -sS -X POST http://localhost:8080/v1/messages \
  -H 'x-api-key: sk-ant-api03-real-key-would-be-wrong-here' \
  -d '{"messages":[{"role":"user","content":"hi"}]}'
#   → 401, "rejected: auth header must carry a registered zkg-* token"
```

## 알려진 한계 (솔직 선언)

1. **HTTP 스택 내부 복사본.** `HeaderValue` 는 `Zeroize` 를 impl 하지 않음.
   zkguard 쪽 Rust 소유권은 한 번에 한 개만 만들고 바로 request 로 move 해서
   owned copy 를 남기지 않지만, reqwest/hyper 가 내부적으로 만드는 버퍼와
   TLS 세션 버퍼는 프로세스 종료 전까지 memset 되지 않을 수 있음. 이 계층의
   복사본까지 지우려면 custom HTTP/TLS 스택이 필요하며 현 scope 밖.

2. **사내·커스텀 토큰 포맷.** 스캐너가 모르는 포맷의 키(예: `internal-xxx`,
   특정 회사 전용 JWT) 는 자동 감지 대상이 아님. strict auth 가 실수 reject 로
   일차 방어는 하지만, 본문에 자유로 박힌 포맷 미인식 키는 redact 되지 않음.

3. **프로세스 메모리 스캔.** 실행 중 프로세스의 주소 공간을 root 가 읽으면
   열린 vault 내용이 있을 수 있음. 이는 OS 레벨 고립·권한 분리 문제이고
   zkguard 가 방어 대상으로 삼는 위협은 아님(설치되는 머신을 이미 탈취한
   공격자는 vault 여부와 무관하게 앱 메모리를 읽을 수 있음).

4. **Python 바인딩.** PyO3 를 거쳐 Python 쪽에 bytes 가 도달하면 GC 특성상
   zeroize 를 보장할 수 없음. 이 경로로 키를 쓰는 사용자는 프록시 기반
   사용을 권장.

5. **KeyCommitAir.** polynomial evaluation 기반. 완전한 Poseidon2-in-AIR 은
   미래 작업(v0.4+).

## 취약점 보고

보안 이슈는 이슈 트래커 대신
<qudgus6993@gmail.com> 으로 비공개 보고 바랍니다.
