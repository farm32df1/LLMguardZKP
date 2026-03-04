# 왜 zkguard인가?

> **LLM 사용 시 API 키 유출을 자동 방지하는 보안 툴킷 (+ 영지식증명 기반 키 소유 검증)**

## 문제: LLM을 통해 API 키가 유출된다

매일 개발자들이 LLM 프롬프트에 실수로 API 키를 붙여넣고 있습니다:

```
"이 코드 디버그해줘: requests.get(url, headers={'Authorization': 'Bearer sk-ant-api03-AAAA...'})"
```

이 프롬프트가 LLM 서버에 도착하는 순간, 당신의 키는:

- 제공자의 로그에 저장됨 (수 개월간 보관 가능)
- 제공자의 직원과 시스템에 노출됨
- 제공자가 데이터 유출 사고를 겪으면 함께 유출됨
- 제공자의 데이터 정책에 따라 향후 모델 학습에 사용될 수 있음

**Enter를 누르는 순간 이미 늦었습니다.**

### 실제 영향

| 시나리오 | 위험 |
|---------|------|
| 하드코딩된 키가 있는 코드를 ChatGPT에 붙여넣기 | 키가 OpenAI 로그에 저장됨 |
| Claude에게 API 연동 디버그 요청 | 키가 Anthropic 시스템에 노출됨 |
| LLM 기반 IDE 어시스턴트 사용 | 코드 완성할 때마다 키가 제공자에게 전송됨 |
| 팀 Slack/문서에 프롬프트 공유 | 키가 여러 서비스에 퍼짐 |
| LLM이 응답에서 키를 그대로 출력 | 터미널/채팅 로그에 키가 나타남 |

### 기존 "해결책"과 한계

| 접근법 | 문제점 |
|--------|--------|
| "키를 붙여넣지 마세요" | 인간의 실수는 필연적. 한 번이면 충분합니다. |
| `.env` 파일 + `.gitignore` | git만 보호할 뿐. LLM 프롬프트는 보호 못함. |
| 시크릿 매니저 (Vault, AWS SM) | 서버용으로 설계됨. LLM 프롬프트 연동 없음. |
| 정규식 린터 (detect-secrets, gitleaks) | 커밋 전 검사만. 실시간 LLM 세션은 가로채지 못함. |
| 제공자 측 스캔 | 이미 늦음 — 키가 이미 당신의 컴퓨터를 떠난 후. |

## zkguard의 접근법: 떠나기 전에 보호

zkguard는 단순한 원칙으로 동작합니다: **키가 애초에 당신의 컴퓨터를 떠나면 안 된다.**

```
당신의 프롬프트: "sk-ant-api03-AAAA...로 API 호출해줘"
                    │
                    ▼  ← 당신의 컴퓨터 (Rust/Python, < 1ms)
            [zkguard.sanitize()]
                    │
                    ▼
안전한 프롬프트: "{{ZKGUARD:a3f2b1c9...}}로 API 호출해줘"
                    │
                    ▼  ← 네트워크
            LLM (Claude, GPT 등)
                    │
           실제 키를 절대 볼 수 없음
```

### 무엇이 다른가

1. **로컬 우선**: 스캔과 교체가 전부 당신의 컴퓨터에서 일어남. LLM은 키를 받지 않음.

2. **자동**: 수동으로 키를 지울 필요 없음. `sanitize()`가 패턴과 엔트로피 분석으로 자동 감지.

3. **왕복 처리**: LLM이 `{{ZKGUARD:...}}` 토큰을 포함한 응답을 보내면, `process_tokens()`가 vault의 실제 키를 사용해 API 호출 가능 — 키를 문자열로 노출하지 않고.

4. **암호학적 증명**: zkguard는 키를 드러내지 않고 키 *소유*를 증명하는 영지식 STARK 증명을 생성할 수 있음. 이를 통해:
   - 감사자에게 유효한 API 인증 정보가 있음을 증명
   - 자동화 파이프라인에서 키 소유 검증
   - 노출 없는 증거 생성

5. **메모리 안전**: vault의 키는 drop 시 자동으로 제로화됨. 키에 접근하는 유일한 방법은 클로저(`with_key()`)를 통하는 것이며, 함수 반환 전에 대여가 끝남.

## 사용 시나리오

### 1. LLM 보조 개발

API 연동을 디버그하면서 Claude/GPT의 도움이 필요할 때:

```python
guard = zkguard.ZkGuard()

# 프롬프트에 실수로 API 키가 포함됨
prompt = f"이 요청이 403을 반환해: curl -H 'x-api-key: {api_key}' https://api.example.com"

# zkguard가 LLM에 도달하기 전에 잡아냄
safe = guard.sanitize(prompt)
response = llm.invoke(safe.content)  # LLM은 {{ZKGUARD:...}}만 보고, 실제 키는 못 봄
```

### 2. LangChain / Agent 파이프라인

LLM 에이전트가 도구 호출 워크플로에서 API 키를 다루는 경우:

```python
from zkguard_langchain import ZkGuardCallbackHandler

# 콜백이 모든 프롬프트와 응답에서 키 유출을 모니터링
llm = ChatAnthropic(
    model="claude-sonnet-4-20250514",
    callbacks=[ZkGuardCallbackHandler(raise_on_leak=True)]
)
# 프롬프트나 응답에서 키가 발견되면 즉시 ValueError 발생
```

### 3. 공유 프롬프트 라이브러리

팀이 공유하는 프롬프트 템플릿에 키가 실수로 포함된 경우:

```python
guard = zkguard.ZkGuard()

# 프롬프트 라이브러리에서 노출된 키 스캔
for prompt in prompt_library:
    result = guard.sanitize(prompt)
    if result.redaction_count > 0:
        print(f"경고: 프롬프트에서 {result.redaction_count}개 키 발견")
        # 정화된 버전을 대신 저장
        save_sanitized(result.content)
```

### 4. 컴플라이언스와 감사

API 키를 노출하지 않고 안전하게 관리하고 있음을 증명:

```python
prover = zkguard.StarkProver()

# 유효한 API 키를 소유하고 있다는 ZK 증명 생성
key_bytes = [ord(c) for c in api_key[:6]]
proof = prover.prove_key_commit(key_bytes)

# 감사자는 키를 보지 않고도 검증 가능
verifier = zkguard.StarkVerifier()
assert verifier.verify(proof)  # True — 키 소유 증명 완료
```

### 5. CI/CD 파이프라인 보호

빌드 로그와 테스트 출력에서 우발적 키 노출 방지:

```bash
# CI 파이프라인에서 텍스트의 키 스캔
echo "$LOG_OUTPUT" | cargo run --features cli -p zkguard -- scan

# 로깅 전 정화
echo "$PROMPT_TEXT" | cargo run --features cli -p zkguard -- sanitize
```

## zkguard가 하지 않는 것

한계를 정직하게 밝히는 것이 중요합니다:

| 한계 | 설명 |
|------|------|
| Vault 암호화는 명시적 opt-in 필요 | `vault-encrypt` feature로 AES-256-GCM + Argon2id 디스크 암호화 가능. 미사용 시 vault 파일은 평문. |
| HTTP 헤더의 키 보호 불가 | `llm-proxy` feature로 HTTP 레벨 보호 가능. |
| 악성 코드 방어 불가 | 코드가 의도적으로 메모리에서 키를 추출하면 zkguard로 막을 수 없음. |
| Python zeroize 미보장 | 키 바이트가 Rust에서 Python으로 넘어오면(콜백 경유) Python의 GC가 관리. 결정적 제로화 불가능. |
| 시크릿 매니저 대체 아님 | zkguard는 LLM 프롬프트를 특정적으로 보호. 범용 시크릿 관리에는 Vault/AWS SM 사용. |

## 성능

| 작업 | 소요 시간 | 비고 |
|------|----------|------|
| `sanitize()` (키 1개) | < 0.1 ms | 정규식 + vault 저장 |
| `sanitize()` (키 10개) | < 0.5 ms | O(n) 단일 패스 교체 |
| `process_tokens()` | < 0.1 ms | 문자열 스캔 + 클로저 호출 |
| STARK 증명 생성 | ~50-200 ms | 키 길이에 따라 다름 |
| STARK 증명 검증 | ~10-50 ms | 생성보다 빠름 |
| Poseidon2 해시 | < 0.01 ms | OnceLock 싱글턴, 첫 호출 이후 할당 없음 |

## 언어 지원

| 언어 | 상태 | 설치 |
|------|------|------|
| Rust | 안정 | `zkguard = { features = ["llm-guard"] }` |
| Python | 안정 | `pip install zkguard` (maturin 빌드) |
| LangChain | 안정 | `from zkguard_langchain import ZkGuardCallbackHandler` |
| Node.js | 계획 (v0.4) | napi-rs 또는 C FFI |

## 요약

zkguard가 존재하는 이유는 **API 키를 보호하는 가장 좋은 시점은 키가 컴퓨터를 떠나기 전**이기 때문입니다. 제공자 측 스캔, 사후 감지, 수동 편집 등 다른 모든 방법은 이미 늦었습니다. zkguard는 보호를 자동적이고, 투명하며, 암호학적으로 검증 가능하게 만듭니다.
