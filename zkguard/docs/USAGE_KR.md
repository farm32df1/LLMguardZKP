# zkguard 사용 가이드

## 동작 원리 (중요)

zkguard는 LLM 서버가 아닌 **사용자의 로컬 머신**에서 실행됩니다. 키 스캔과 교체는 텍스트가 컴퓨터를 떠나기 **전에** 일어납니다.

```
사용자 입력: "API 호출에 sk-ant-api03-AAAA... 사용"
      │
      ▼  ← 로컬 (사용자 PC, Rust/Python 코드)
 [zkguard.sanitize()]
      │
      ▼
 안전한 텍스트: "API 호출에 {{ZKGUARD:a3f2...}} 사용"
      │
      ▼  ← 네트워크 (LLM 서버로 전송)
 LLM (Claude, GPT 등)  ← 실제 키를 절대 볼 수 없음
```

LLM이 키를 스캔하는 것이 아닙니다. zkguard가 로컬에서 스캔하고, LLM이 텍스트를 받기 전에 교체합니다.

## 목차

1. [설치](#설치)
2. [빠른 시작 — 간편 API (모두를 위한)](#빠른-시작--간편-api-모두를-위한)
3. [빠른 시작 — 전체 API (개발자용)](#빠른-시작--전체-api-개발자용)
4. [빠른 시작 (Rust)](#빠른-시작-rust)
5. [API 키 스캔](#api-키-스캔)
6. [LLM 프롬프트 보호](#llm-프롬프트-보호)
7. [LLM 출력 처리](#llm-출력-처리)
8. [암호화 Vault](#암호화-vault)
9. [ZK 증명](#zk-증명)
10. [LangChain 통합](#langchain-통합)
11. [Rust CLI](#rust-cli)
12. [보안 참고사항](#보안-참고사항)

---

## 설치

### Python (LLM 사용자 추천)

```bash
# 소스에서 빌드 (Rust 툴체인 필요)
cd bindings/python
pip install maturin
maturin develop --features stark

# 또는 wheel 파일 직접 설치
pip install zkguard-0.2.0-cp38-abi3-*.whl
```

### Rust

```toml
# Cargo.toml
[dependencies]
zkguard = { path = "crates/zkguard-core", features = ["llm-guard"] }
```

### LangChain 통합

```bash
pip install zkguard langchain-core
```

---

## 빠른 시작 — 간편 API (모두를 위한)

설정 없이, 한 줄이면 됩니다.

```python
import zkguard

# 텍스트에서 모든 API 키 제거
safe = zkguard.clean("디버그: curl -H 'x-api-key: sk-ant-api03-AAAA...' https://api.anthropic.com")
# → "디버그: curl -H 'x-api-key: [PROTECTED]' https://api.anthropic.com"

# 텍스트에 키가 있는지 확인
zkguard.has_keys("AKIAIOSFODNN7EXAMPLE")   # True
zkguard.has_keys("일반 텍스트")             # False

# 상세 스캔
keys = zkguard.scan("여기에 AKIAIOSFODNN7EXAMPLE 사용")
# → [{"provider": "AWS Access Key", "position": (4, 24)}]

# 상세 리포트
report = zkguard.safe_prompt("sk-ant-api03-...와 AKIAIOSFODNN7EXAMPLE 사용")
# → {"text": "[PROTECTED]와 [PROTECTED] 사용", "found": 2, "providers": ["Anthropic", "AWS Access Key"]}

# LLM 호출 함수 자동 보호
safe_llm = zkguard.wrap_fn(your_openai_call)
safe_llm(messages=[{"role": "user", "content": "key=sk-ant-api03-..."}])
# → LLM은 실제 키를 절대 보지 못함
```

### 간편 API 레퍼런스

| 함수 | 설명 |
|------|------|
| `clean(text, placeholder="[PROTECTED]")` | 모든 API 키를 제거하고 깨끗한 텍스트 반환 |
| `has_keys(text)` | 텍스트에 API 키가 있는지 확인 (True/False) |
| `scan(text)` | 모든 API 키를 찾고 provider와 position이 포함된 dict 리스트 반환 |
| `safe_prompt(text)` | 텍스트를 보호하고 text, found 수, providers가 포함된 dict 반환 |
| `wrap_fn(fn, placeholder="[PROTECTED]")` | 함수를 래핑하여 문자열 인자를 자동 보호 |

---

## 빠른 시작 — 전체 API (개발자용)

```python
import zkguard

# guard 인스턴스 생성
guard = zkguard.ZkGuard()

# API 키가 실수로 포함된 텍스트
text = "API 호출에 키 sk-ant-api03-AAAA...AAAA를 사용하세요"

# 1단계: 보호 — 키가 안전한 토큰으로 교체됨
result = guard.sanitize(text)
print(result.content)
# → "API 호출에 키 {{ZKGUARD:a3f2b1c9...}}를 사용하세요"
print(f"{result.redaction_count}개 키 제거: {result.providers}")

# 2단계: 보호된 텍스트를 LLM에 전송 (안전 — 키 노출 없음)
llm_response = call_your_llm(result.content)

# 3단계: LLM 출력에 토큰이 있으면 처리
final = guard.process_tokens(llm_response, lambda token: "[키_사용됨]")
```

### 무슨 일이 일어났나?

1. `sanitize()`가 텍스트에서 API 키를 스캔 (Anthropic, OpenAI, AWS, Google)
2. 각 키가 안전한 인메모리 vault에 저장됨
3. 키가 `{{ZKGUARD:<id>}}` 토큰으로 교체됨
4. LLM은 토큰만 보고, 실제 키는 절대 볼 수 없음
5. `process_tokens()`로 LLM 출력의 토큰을 처리

---

## 빠른 시작 (Rust)

```rust
use zkguard::llm_guard::ContextSanitizer;

let mut guard = ContextSanitizer::new();

// 보호
let result = guard.sanitize("키 sk-ant-api03-AAAA...AAAA를 사용하세요").unwrap();
assert!(!result.content.contains("sk-ant-"));

// LLM 출력의 토큰 처리
let output = guard.process_tokens(&result.content, |vault, handle| {
    vault.with_key(handle, |key_bytes| {
        // key_bytes로 실제 API 호출
        Ok("[API_응답]".to_string())
    })
}).unwrap();
```

---

## API 키 스캔

### 지원 프로바이더

| 프로바이더 | 패턴 | 예시 접두사 |
|-----------|------|-----------|
| Anthropic | `sk-ant-*` (93자 이상) | `sk-ant-api03-...` |
| OpenAI | `sk-` (48자) | `sk-abc123...` |
| OpenAI Project | `sk-proj-*` (100자 이상) | `sk-proj-...` |
| AWS Access Key | `AKIA` (20자) | `AKIAIOSFODNN7...` |
| Google AI | `AIza` (39자) | `AIzaSyB...` |
| Unknown | 높은 엔트로피 문자열 | (자동 감지) |

### 스캔만 수행 (텍스트 수정 없음)

```python
scanner = zkguard.ContextScanner()
keys = scanner.scan("내 키는 AKIAIOSFODNN7EXAMPLE 입니다")

for key in keys:
    print(f"프로바이더: {key.provider}")
    print(f"위치: {key.span}")  # (시작, 끝) 바이트 오프셋
```

참고: `DetectedKey.value`는 Python에서 의도적으로 비노출합니다. 원본 키 바이트는 zeroize 보호가 적용된 Rust 메모리에 남아있습니다. 필요하면 span으로 원본 텍스트에서 추출할 수 있습니다.

---

## LLM 프롬프트 보호

### 기본 사용법

```python
guard = zkguard.ZkGuard()

# 텍스트 보호 — 모든 API 키를 감지하고 교체
result = guard.sanitize("sk-ant-api03-...와 AKIAIOSFODNN7EXAMPLE로 연결")

print(result.content)         # {{ZKGUARD:...}} 토큰이 포함된 텍스트
print(result.redaction_count) # 발견된 키 수
print(result.providers)       # ["Anthropic", "AWS Access Key"]
```

### 수동 키 저장

```python
guard = zkguard.ZkGuard()

# 키를 수동으로 저장 (텍스트 스캔이 아닌 직접 등록)
token = guard.store_key(b"my-secret-api-key")
print(token)  # "{{ZKGUARD:a1b2c3...}}"

# 프롬프트에서 토큰 사용
prompt = f"인증에 {token}을 사용하세요"
```

### 텍스트에서 토큰 찾기

```python
tokens = guard.find_tokens("{{ZKGUARD:abc123...}}을 사용하세요")
print(tokens)  # ["{{ZKGUARD:abc123...}}"]
```

---

## LLM 출력 처리

LLM이 `{{ZKGUARD:...}}` 토큰을 포함한 텍스트를 반환하면, `process_tokens()`로 처리합니다.

### 토큰을 레이블로 교체

```python
output = guard.process_tokens(
    llm_response,
    lambda token: "[비공개]"
)
```

### 커스텀 로직으로 토큰 교체

```python
def handle_token(token):
    # token은 전체 "{{ZKGUARD:hex}}" 문자열
    # 교체할 문자열을 반환
    return f"<키:{token[:20]}...>"

output = guard.process_tokens(llm_response, handle_token)
```

### 전형적인 왕복 흐름

```python
guard = zkguard.ZkGuard()

# 1. 사용자 입력에 실수로 키가 포함됨
user_input = f"날씨 API 호출에 {api_key}를 사용해주세요"

# 2. LLM에 보내기 전 보호
safe = guard.sanitize(user_input)

# 3. LLM에 전송 (키 보호됨)
llm_output = your_llm.invoke(safe.content)

# 4. LLM 출력 처리
final = guard.process_tokens(llm_output, lambda t: "[API_호출됨]")
```

---

## 암호화 Vault

zkguard는 AES-256-GCM과 Argon2id 키 유도를 사용하여 vault를 디스크에 암호화할 수 있습니다. 저장된 API 키를 정지 상태에서 보호합니다.

### Python

```python
guard = zkguard.ZkGuard()

# 키 저장
guard.sanitize("key=sk-ant-api03-AAAA...AAAA")

# 암호화 저장 (AES-256-GCM + Argon2id, 64 MiB 메모리 하드)
guard.save_encrypted("vault.enc", b"my-strong-password")

# 비밀번호로 로드
loaded = zkguard.ZkGuard.load_encrypted("vault.enc", b"my-strong-password")
assert loaded.vault_size == 1

# 커스텀 Argon2id 매개변수 (테스트용 빠른 설정 또는 보안 강화)
guard.save_encrypted("vault.enc", b"password", m_cost=1024, t_cost=1, p_cost=1)
```

### Rust

```rust
use zkguard::{SecretVault, save_vault_encrypted, load_vault_encrypted, VaultEncryptionParams};

let mut vault = SecretVault::new();
vault.store(b"sk-ant-api03-secret-key").unwrap();

// 암호화 저장
let params = VaultEncryptionParams::default(); // 64 MiB, 3회 반복
save_vault_encrypted(&vault, "vault.enc".as_ref(), b"my-password", &params).unwrap();

// 비밀번호로 로드
let loaded = load_vault_encrypted("vault.enc".as_ref(), b"my-password").unwrap();

// 평문 vault를 암호화 vault로 마이그레이션
use zkguard::migrate_vault_to_encrypted;
migrate_vault_to_encrypted("vault.bin".as_ref(), "vault.enc".as_ref(), b"password", &params).unwrap();
```

### 보안 참고

- 기본 Argon2id 매개변수: 64 MiB 메모리, 3회 반복, 병렬 1 (GPU/ASIC 방어)
- 파일 형식 v2: 매직 바이트 "ZKGE", 자체 포함 KDF 매개변수
- Unix에서 vault 파일은 0600 권한으로 기록
- 모든 평문 버퍼는 암호화 후 zeroize
- 잘못된 비밀번호는 에러 반환 (AEAD 태그 불일치로 복호화 실패)

---

## ZK 증명

zkguard는 데이터를 드러내지 않고 소유를 증명하는 영지식 STARK 증명을 생성할 수 있습니다.

### 키 소유 증명

```python
prover = zkguard.StarkProver()

# 필드 원소의 지식 증명 (예: 키 바이트를 정수로)
key_bytes = [ord(c) for c in "sk-ant"]  # [115, 107, 45, 97, 110, 116]
proof = prover.prove_key_commit(key_bytes)

print(proof.air_type)       # "KeyCommit"
print(proof.num_rows)       # trace 크기
print(proof.public_values)  # [eval_final, num_elements]
```

### 증명 검증

```python
verifier = zkguard.StarkVerifier()
is_valid = verifier.verify(proof)
print(f"유효: {is_valid}")  # True
```

### 직렬화 / 역직렬화

```python
# 바이너리 (컴팩트)
data = proof.to_bytes()              # bytes
restored = zkguard.StarkProof.from_bytes(data)

# JSON (사람이 읽을 수 있음)
json_str = proof.to_json()           # str
restored = zkguard.StarkProof.from_json(json_str)
```

### 피보나치 증명 (예제)

```python
prover = zkguard.StarkProver()
proof = prover.prove_fibonacci(8)  # 8행 (2의 거듭제곱, 4 이상)

verifier = zkguard.StarkVerifier()
assert verifier.verify(proof)
```

---

## LangChain 통합

### Callback Handler (모니터링)

LLM 프롬프트와 출력에서 API 키를 감지합니다. 모든 LangChain 버전에서 동작합니다.

```python
from zkguard_langchain import ZkGuardCallbackHandler

# 경고 모드 (기본) — 키 감지 시 경고 출력
handler = ZkGuardCallbackHandler()

# 엄격 모드 — 키 감지 시 ValueError 발생
handler = ZkGuardCallbackHandler(raise_on_leak=True)

# 커스텀 로깅
handler = ZkGuardCallbackHandler(log_fn=my_logger.warning)

# LangChain LLM과 함께 사용
from langchain_anthropic import ChatAnthropic
llm = ChatAnthropic(
    model="claude-sonnet-4-20250514",
    callbacks=[handler]
)

# 호출 후 감지된 키 확인
print(f"누출 발견: {handler.leak_count}")
print(f"상세: {handler.detected_keys}")

# 카운터 초기화
handler.reset()
```

### Callback이 스캔하는 것

| 이벤트 | 스캔 대상 |
|-------|----------|
| `on_llm_start` | LLM에 보내기 전 프롬프트 |
| `on_chat_model_start` | 보내기 전 채팅 메시지 |
| `on_llm_end` | LLM 응답 텍스트 |

---

## Rust CLI

```bash
# CLI 빌드
cargo build --features cli -p zkguard

# 텍스트에서 키 스캔
echo "key=sk-ant-api03-AAAA..." | cargo run --features cli -p zkguard -- scan

# 텍스트 보호
echo "key=AKIAIOSFODNN7EXAMPLE" | cargo run --features cli -p zkguard -- sanitize

# ZK 증명 생성
cargo run --features cli -p zkguard -- prove --elements 115,107,45 --output proof.bin

# 증명 검증
cargo run --features cli -p zkguard -- verify --input proof.bin

# 전체 데모
cargo run --features cli -p zkguard -- demo
```

---

## 보안 참고사항

### zkguard가 보호하는 것

- LLM 프롬프트에 실수로 포함된 API 키
- LLM 컨텍스트 윈도우를 통한 키 유출
- LLM 응답에서 키가 에코되는 것
- 공유 프롬프트/로그에서 감지되지 않은 키 노출

### zkguard가 보호하지 않는 것

- 환경 변수에 저장된 키 (`.env` 파일)
- HTTP 헤더의 키 (`llm-proxy` feature로 부분 대응)
- 데이터베이스 연결의 키
- 악성 코드에 의한 의도적 키 추출

### Python 보안 한계

**중요**: 키 바이트가 Rust에서 Python으로 넘어오면 (`process_tokens` 콜백 내부), Python의 가비지 컬렉터 관리 메모리에 들어갑니다. Rust의 `zeroize` 보장은 Python 메모리에 적용되지 않습니다. 키 바이트는 Python GC가 수거할 때까지 메모리에 남습니다.

최대 보안을 위해 Rust 라이브러리를 직접 사용하거나, `process_tokens` 콜백 내에서 키 바이트를 저장하지 않고 처리하세요.

### Poseidon2 해시

```python
# 도메인 분리된 Poseidon2 해시
h = zkguard.poseidon_hash(b"data", b"my_domain")
# 32 바이트 (256비트 다이제스트) 반환
```

모든 내부 해싱은 고유한 도메인 태그를 가진 Poseidon2를 사용하여 교차 컨텍스트 충돌을 방지합니다.

---

## API 레퍼런스

### Python 클래스

| 클래스 | 설명 |
|-------|------|
| `ContextScanner` | 텍스트에서 API 키 스캔 |
| `DetectedKey` | 감지된 키 정보 (provider, span) |
| `ZkGuard` | 메인 오케스트레이터 (스캔 + vault + 토큰) |
| `SanitizedResult` | sanitize() 결과 |
| `StarkProver` | STARK 증명 생성 |
| `StarkVerifier` | STARK 증명 검증 |
| `StarkProof` | 직렬화 가능한 증명 객체 |

### 간편 API 함수

| 함수 | 설명 |
|------|------|
| `clean(text, placeholder)` | 텍스트에서 모든 API 키 제거 |
| `has_keys(text)` | 텍스트에 API 키 있는지 확인 |
| `scan(text)` | 모든 API 키를 찾고 dict 반환 |
| `safe_prompt(text)` | 보호 + 상세 정보 반환 |
| `wrap_fn(fn, placeholder)` | 함수를 자동 보호 래핑 |

### Python 함수

| 함수 | 설명 |
|------|------|
| `poseidon_hash(data, domain)` | 도메인 분리된 Poseidon2 해시 |

### 상수

| 상수 | 설명 |
|------|------|
| `VERSION` | 라이브러리 버전 문자열 |
