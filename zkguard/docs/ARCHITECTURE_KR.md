# zkguard 아키텍처

## 개요

zkguard는 LLM 사용 시 API 키 유출을 자동 방지하는 보안 툴킷입니다. **컨텍스트 새니타이제이션**(키 자동 감지 및 제거), **리버스 프록시**(모든 앱에 투명한 보호), **영지식 증명**(키를 노출하지 않고 소유를 증명)을 결합합니다.

```
┌─────────────────────────────────────────────────────────────┐
│                       사용자 애플리케이션                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   사용자 프롬프트 ──→ ContextSanitizer.sanitize()             │
│                          │                                  │
│                          ├── ContextScanner (키 감지)        │
│                          ├── SecretVault (키 저장)            │
│                          └── HandleId (불투명 토큰)           │
│                                                             │
│   새니타이즈된 프롬프트 ──→ LLM API 호출 (시크릿 없음!)        │
│                                                             │
│   LLM 응답 ──→ ContextSanitizer.process_tokens()             │
│                    │                                        │
│                    └── vault.with_key() 클로저               │
│                         └── 실제 API 호출 수행               │
│                                                             │
│   [선택] StarkProver.prove_key_commit()                      │
│              └── 키 소유의 ZK 증명                           │
│                                                             │
│   [선택] StarkVerifier.verify_key_commit()                   │
│              └── 제3자 검증                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 데이터 흐름

### 정방향 경로 (새니타이제이션)

```
사용자 입력           ContextScanner          SecretVault          출력
─────────────       ──────────────          ───────────          ──────
"키를 사용해주세요    정규식 스캔              store(key_bytes)     "키를 사용해주세요
 sk-ant-api03-..."   엔트로피 스캔  ──────→  → KeyHandle          {{ZKGUARD:a3f2...}}
                     → DetectedKey           → HandleId           ..."
                                             → zeroize-on-drop
```

1. `ContextScanner.scan()`이 컴파일된 정규식 패턴(OnceLock)과 Shannon 엔트로피 휴리스틱으로 API 키를 감지
2. 감지된 각 키에 대해 `SecretVault.store()`가 키 데이터를 암호화하여 저장하고 `KeyHandle`을 반환
3. 원본 텍스트의 키가 `{{ZKGUARD:<hex-id>}}`로 대체
4. `KeyHandle`이 `ContextSanitizer`의 핸들 레지스트리(`BTreeMap<HandleId, KeyHandle>`)에 등록

### 역방향 경로 (토큰 해석)

```
LLM 출력             핸들 레지스트리          SecretVault          동작
──────────          ───────────────          ───────────          ──────
"API를 호출합니다     "{{ZKGUARD:..." 탐색    with_key(handle,     클로저가 원시 키
 {{ZKGUARD:a3f2..}}  → hex id 파싱           |key_bytes| {       바이트를 받아
 결과를 반환"         → KeyHandle 조회         // API 호출        HTTP 호출 수행,
                                             })                  결과 반환
```

1. `process_tokens()`가 LLM 출력에서 `{{ZKGUARD:<hex>}}` 패턴을 스캔
2. 각 토큰이 핸들 레지스트리를 통해 해당 `KeyHandle`로 해석
3. 호출자의 클로저가 `(&SecretVault, &KeyHandle)`을 수신 — `vault.with_key()`로 원시 키 접근
4. 키는 반환 문자열에 **절대** 나타나지 않음 — 클로저의 반환값만 사용

### ZK 증명 경로 (선택)

```
키 데이터             StarkProver              StarkVerifier
────────────         ───────────              ─────────────
bytes_to_fields()    prove_key_commit()       verify_key_commit()
→ Vec<u64>           → 다항식 평가             → 증명 검증
                     → STARK 트레이스          → 공개 값만 확인
                     → FRI 커밋               → 키 노출 없음
                     → StarkProof
```

1. 키 바이트가 `bytes_to_fields()`를 통해 Goldilocks 필드 원소로 변환
2. `KeyCommitAir`가 다항식 평가를 계산: `eval = Σ(key[i] * ALPHA^i)`, `ALPHA = 0x7A4B_4755_4152_4431`
3. STARK 증명이 키 값을 노출하지 않고 트레이스에 커밋
4. 검증자는 `(eval, num_elements)`만 확인 — 키 지식을 확인하기에 충분하지만 키를 복원하기에는 불충분

## 모듈 아키텍처

### core/ — 기본 타입

```
errors.rs ──→ ZKGuardError 열거형 (11개 변형)
              Result<T> 타입 별칭

types.rs  ──→ CommittedPublicInputs (Poseidon2 커밋먼트)
              Proof, Witness, PublicInputs

traits.rs ──→ Prover<Input, Output> 트레이트
              Verifier<Proof, Output> 트레이트
```

### stark/ — Plonky3 STARK 통합

```
air.rs ──────────→ SimpleAir { Fibonacci, Sum, Multiplication }
                   p3_air::Air<AB> 구현

range_air.rs ────→ RangeCheckAir (값이 [0, max] 범위 내 증명)

key_commit_air.rs → KeyCommitAir (다항식 평가 회로)
                   WIDTH = 3 컬럼: [value, eval, alpha_power]
                   MAX_KEY_ELEMENTS = 512

real_stark.rs ───→ StarkProver  (p3-uni-stark prove() 래핑)
                   StarkVerifier (p3-uni-stark verify() 래핑)
                   StarkProof { 트레이스 데이터, 공개 값, 행 수 }

                   메서드:
                   - prove_fibonacci / verify_fibonacci
                   - prove_sum / verify_sum
                   - prove_multiplication / verify_multiplication
                   - prove_range / verify_range
                   - prove_key_commit / verify_key_commit

config.rs ───────→ StarkConfig { security_bits, fri_queries, ... }
                   validate() — constants.rs의 경계값으로 검증
```

### utils/ — 암호학 유틸리티

```
hash.rs ─────────→ get_poseidon2() — OnceLock 싱글턴
                   poseidon2_hash(domain, data) → [u8; 32]
                   bytes_to_fields(bytes) → Vec<u64>
                   combine_hashes() — 스택 기반 결합
                   constant_time_eq_fixed() — 사이드채널 방어

constants.rs ────→ 모든 수치 상수의 단일 소스
                   Poseidon2: WIDTH, RATE, OUTPUT_SIZE, SEED
                   FRI: LOG_BLOWUP, NUM_QUERIES, POW_BITS
                   Config: SECURITY_BITS_MIN/MAX, FRI_QUERIES_MIN/MAX
                   Handle: ID_BYTES, BINDING_SIZE
                   Scanner: ENTROPY_THRESHOLD, MIN/MAX_TOKEN_LEN
                   16개 도메인 분리 태그 (ZKGUARD::*)

compression.rs ──→ RLE 압축 + 무결성 체크섬
                   압축 해제 폭탄 방어 (MAX_RLE_DECOMPRESSED_SIZE)
```

### batching/ — 증명 집계

```
merkle.rs ───────→ MerkleTree (Poseidon2 기반)
                   도메인 분리된 노드 해싱

mod.rs ──────────→ ProofBatch { proofs, merkle_root }
                   배치 검증
```

### llm_guard/ — LLM API 키 보호

```
scanner.rs ──────→ ContextScanner
                   - 5개 정규식 패턴 (OnceLock, 1회만 컴파일)
                   - Shannon 엔트로피 휴리스틱 (미지 형식용)
                   - 스팬 중복 제거 (Anthropic > OpenAI)

                   DetectedKey { provider, value (Zeroize), span }
                   ApiProvider 열거형 (6개 변형)

vault.rs ────────→ SecretVault
                   - BTreeMap<HandleId, VaultEntry>
                   - store(key_bytes) → KeyHandle
                   - with_key(handle, closure) → Result
                   - revoke(handle_id) — vault에서 제거
                   - 모든 항목에 Zeroize on drop 적용

handle.rs ───────→ HandleId([u8; 16]) — 불투명 식별자
                   KeyHandle { id, commitment, binding }
                   - to_token() → "{{ZKGUARD:<hex>}}"
                   - is_valid() → 바인딩 무결성 검증
                   - from_hex() → hex 문자열 파싱

                   Poseidon2 커밋먼트가 핸들과 키를 바인딩

sanitizer.rs ────→ ContextSanitizer (메인 API 표면)
                   - sanitize(text) → SanitizedText
                   - process_tokens(text, closure) → String
                   - from_vault(vault) — 로드된 vault로 생성
                   - vault() / vault_mut() — vault 접근
                   - handle_count() — 레지스트리 크기

                   내부 소유:
                   - SecretVault
                   - ContextScanner
                   - BTreeMap<HandleId, KeyHandle> (레지스트리)

audit.rs ────────→ AuditLog
                   - 해시 체인 무결성 (DOMAIN_AUDIT_ENTRY)
                   - 추가 전용 이벤트 로그

persistence.rs ──→ save_vault / load_vault
                   - MAC 검증 평문 파일 형식

encrypted_persistence.rs → 암호화 vault (vault-encrypt feature)
                   - AES-256-GCM + Argon2id 키 유도
                   - 파일 형식 v2: 매직 "ZKGE" + KDF 매개변수 + 암호문
                   - save_vault_encrypted / load_vault_encrypted
                   - migrate_vault_to_encrypted

proxy.rs ────────→ LlmProxy (llm-proxy feature)
                   - reqwest 기반 HTTP 프록시 (LLM API 호출)
```

## 암호학 설계

### Poseidon2 해시

- **너비**: 16 필드 원소 (rate=8, capacity=8)
- **S-box**: x^7 (대수적 차수 7)
- **시드**: `0x5A4B_4755_4152_4432` (ASCII "ZKGUARD2")
- **초기화**: `OnceLock` 싱글턴 — 1회 계산 후 재사용
- **도메인 분리**: 모든 호출에 고유한 `ZKGUARD::*` 태그를 포함하여 교차 컨텍스트 해시 충돌 방지

### STARK 증명 시스템

- **프레임워크**: Plonky3 (투명, 양자 후 보안)
- **필드**: Goldilocks (p = 2^64 - 2^32 + 1)
- **FRI 매개변수**:
  - `log_blowup = 2` (4배 blowup)
  - `num_queries = 60`
  - `proof_of_work_bits = 8`
  - 사운드니스: 2 × 60 + 8 = 128비트

### KeyCommitAir 회로

키 커밋먼트 회로는 다항식 평가를 통해 키 지식을 증명합니다:

```
트레이스 컬럼: [value, eval, alpha_power]

행 0:   value=key[0]  eval=key[0]              alpha_power=ALPHA
행 i:   value=key[i]  eval=eval+key[i]*alpha^i  alpha_power=alpha^(i+1)

공개 출력: (final_eval, num_elements)
```

- `ALPHA = 0x7A4B_4755_4152_4431` (도메인별 평가 포인트)
- 다른 키는 다른 `(eval, num_elements)` 쌍을 생성
- 검증자는 평가 포인트만 확인 — 키 계수 복원 불가

### SecretVault 보안 모델

```
   store(key_bytes)
        │
        ▼
   ┌─────────────┐
   │  VaultEntry  │
   │  ┌─────────┐ │
   │  │key_data │ │ ← Zeroize + ZeroizeOnDrop
   │  │(Vec<u8>)│ │
   │  └─────────┘ │
   │  commitment   │ ← Poseidon2(DOMAIN_KEY_COMMIT, key_data)
   │  handle_id    │ ← 랜덤 16바이트 (getrandom)
   └──────┬────────┘
          │
          ▼
   with_key(handle, |bytes| { ... })
        │
        └── 클로저가 &[u8] 수신 — 키는 값으로 반환되지 않음
```

핵심 원칙:
1. 키는 `store()`로 진입하고 `with_key()` 클로저로만 사용 가능
2. 모든 키 데이터는 `Zeroize + ZeroizeOnDrop` 구현
3. `Debug` 구현은 비밀 필드를 마스킹
4. 핸들 바인딩은 `DOMAIN_KEY_HANDLE` 태그로 Poseidon2 사용
5. 바인딩 검증은 `constant_time_eq_fixed` 사용

## 상수 관리

모든 수치 상수는 `src/utils/constants.rs`에 중앙 집중화:

| 카테고리 | 상수 | 목적 |
|---------|------|------|
| Poseidon2 | WIDTH, RATE, OUTPUT_SIZE, SEED | 해시 함수 매개변수 |
| FRI | LOG_BLOWUP, NUM_QUERIES, POW_BITS | 증명 시스템 사운드니스 |
| Config | SECURITY_BITS_MIN/MAX, FRI_QUERIES_MIN/MAX | 검증 경계값 |
| Handle | ID_BYTES, BINDING_SIZE | 불투명 참조 크기 |
| Scanner | ENTROPY_THRESHOLD, MIN/MAX_TOKEN_LEN | 키 감지 튜닝 |
| KeyCommit | WIDTH, MAX_KEY_ELEMENTS | AIR 회로 차원 |
| Compression | RLE_SIZE_THRESHOLD | 압축 트리거 |
| 도메인 | 16개 고유 ZKGUARD:: 태그 | 해시 도메인 분리 |

애플리케이션 코드에 매직넘버 없음 — 모든 수치 리터럴은 `constants.rs`에서 가져옴.

## 에러 처리

```rust
enum ZKGuardError {
    InvalidProof { reason: String },
    VerificationFailed { reason: String },
    InvalidInput { reason: String },
    SerializationError { reason: String },
    ProverError { reason: String },
    ConfigError { reason: String },
    KeyNotFound,
    VaultError { reason: String },
    HandleError { reason: String },
    CompressionError { reason: String },
    DecompressionError { reason: String },
}
```

- verify 메서드는 `stark_verify_result()` 사용 — 에러를 삼키지 않고 전파
- `Ok(true)` = 유효한 증명, `Err(VerificationFailed)` = 사유가 포함된 무효 증명

## 테스트 전략

### 단위 테스트 (llm-guard 포함 시 77개, vault-encrypt 포함 시 87개)

각 모듈에 `#[cfg(test)] mod tests`가 포함되어 다음을 검증:
- 정상 경로 동작
- 엣지 케이스 (빈 입력, 잘못된 데이터, 경계값)
- 에러 조건 (무효 핸들, 폐기된 키)
- 상수 일관성 검사

### 퍼즈 테스트 (proptest 기반 20개)

`tests/fuzz_tests.rs` — proptest 기반 속성 테스트:
- scanner, sanitizer, vault에 대한 랜덤 입력 퍼징
- 임의 키 패턴 및 엣지 케이스
- 라운드트립 일관성 검증

### 통합 테스트 (14개 시나리오)

`tests/llm_scenarios.rs` — 엔드투엔드 시나리오:

| # | 시나리오 | 검증 항목 |
|---|---------|----------|
| 1 | Anthropic 키 라운드트립 | sanitize → LLM → process_tokens → with_key |
| 2 | 다중 프로바이더 (Anthropic+AWS) | 2개 키 감지 + 개별 처리 |
| 3 | ZK 키 소유 증명 | STARK prove + verify (KeyCommitAir) |
| 4 | 전체 파이프라인 | sanitize + ZK 증명 + LLM 호출 + 독립 검증 |
| 5 | 키 폐기 | sanitize 후 vault 상태 확인 |
| 6 | 폐기된 핸들 거부 | revoke 후 with_key 실패 |
| 7 | 핸들 무결성 검증 | is_valid() + with_key() |
| 8 | LLM 응답 토큰 없음 | 패스스루, 클로저 미호출 |
| 9 | 다중 턴 대화 | 동일 토큰 여러 번 사용 |
| 10 | 코드 스니펫 속 키 | 코드 구조 보존 + 키 치환 |
| 11 | ZK 증명 바인딩 | 다른 키 → 다른 eval 값 |
| 12 | 커밋먼트 일관성 | vault 저장 + 핸들 접근자 |
| 13 | Google AI 키 감지 | AIza 접두사 감지 |
| 14 | 텍스트 보존 | 키 주변 텍스트 정확히 유지 |

### 예제 (실행 가능한 데모 3개)

- `basic_proof.rs` — STARK 피보나치 증명 생성 및 검증
- `key_protection.rs` — API 키 새니타이제이션
- `full_demo.rs` — 타이밍 출력 포함 전체 7단계 파이프라인
