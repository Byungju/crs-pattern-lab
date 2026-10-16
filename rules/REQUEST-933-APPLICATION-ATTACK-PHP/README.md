# REQUEST-933-APPLICATION-ATTACK-PHP.conf — 쉽게 읽는 분석

> 이 문서는 `REQUEST-933-APPLICATION-ATTACK-PHP.conf` 룰을 "기초 → 룰 → 공격 예제 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터, 3/4=응답, 5=로깅.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝(또는 phase 4 끝)에 `949110`/`959110` 이 임계값을 넘으면 차단.
- **paranoia level(PL)**: 1~4. 구간 사이 게이팅 룰(`…011`~`…018`)이 있다.

> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> PHP 코드/함수 삽입 공격을 탐지한다.

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [933011](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [933012](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [933100](933100.md) | 2 | 1 | CRITICAL | PHP Injection Attack: PHP Open Tag Found |
| [933110](933110.md) | 2 | 1 | CRITICAL | PHP Injection Attack: PHP Script File Upload Found |
| [933120](933120.md) | 2 | 1 | CRITICAL | PHP Injection Attack: Configuration Directive Found |
| [933130](933130.md) | 2 | 1 | CRITICAL | PHP Injection Attack: Variables Found |
| [933135](933135.md) | 2 | 1 | CRITICAL | PHP Injection Attack: Variable Access Found |
| [933140](933140.md) | 2 | 1 | CRITICAL | PHP Injection Attack: I/O Stream Found |
| [933200](933200.md) | 2 | 1 | CRITICAL | PHP Injection Attack: Wrapper scheme detected |
| [933150](933150.md) | 2 | 1 | CRITICAL | PHP Injection Attack: High-Risk PHP Function Name Found |
| [933160](933160.md) | 2 | 1 | CRITICAL | PHP Injection Attack: High-Risk PHP Function Call Found |
| [933170](933170.md) | 2 | 1 | CRITICAL | PHP Injection Attack: Serialized Object Injection |
| [933180](933180.md) | 2 | 1 | CRITICAL | PHP Injection Attack: Variable Function Call Found |
| [933210](933210.md) | 2 | 1 | CRITICAL | PHP Injection Attack: Variable Function Call Found |
| [933220](933220.md) | 2 | 1 | CRITICAL | PHP Injection Attack: PHP Session File Upload Attempt |
| [933013](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [933014](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [933151](933151.md) | 2 | 2 | CRITICAL | PHP Injection Attack: Medium-Risk PHP Function Name Found |
| [933152](933152.md) | 2 | 2 | CRITICAL | PHP Injection Attack: Medium-Risk PHP Function Name Found |
| [933153](933153.md) | 2 | 2 | CRITICAL | PHP Injection Attack: Medium-Risk PHP Function Name Found |
| [933015](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [933016](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [933131](933131.md) | 2 | 3 | CRITICAL | PHP Injection Attack: Variables Found |
| [933161](933161.md) | 2 | 3 | CRITICAL | PHP Injection Attack: Low-Value PHP Function Call Found |
| [933111](933111.md) | 2 | 3 | CRITICAL | PHP Injection Attack: PHP Script File Upload Found |
| [933190](933190.md) | 2 | 3 | CRITICAL | PHP Injection Attack: PHP Closing Tag Found |
| [933211](933211.md) | 2 | 3 | CRITICAL | PHP Injection Attack: Variable Function Call Found |
| [933017](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [933018](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |

---

## 3. 공격 예제 및 실측

| ID | 공격 예제(요청) | HTTP |
|----|------------------|------|
| [933100](933100.md) | `/?x=%3C?php%20system('id');%20?%3E` | **403** |
| [933160](933160.md) | `/?x=%3C?php%20system('id');%20?%3E` | **403** |
| [933161](933161.md) | `/?x=%3C?php%20system('id');%20?%3E` | **403** |
| [933190](933190.md) | `/?x=%3C?php%20system('id');%20?%3E` | **403** |
| [933152](933152.md) | `/?x=phpinfo()` | **403** |
| [933120](933120.md) | `/?x=auto_prepend_file=/etc/passwd` | **403** |

> 그 외 룰은 nginx 도달 불가/조건 필요라 `tests/<id>.sh` 에서 SKIP 처리했다. (PL 게이팅 룰은 테스트에서 제외)

---

## 4. 흐름 / 관계

- 매칭된 룰이 점수를 누적하고, 실제 차단은 **`949110`(요청)/`959110`(응답)** 이 수행한다.
- 파일은 PL 구간으로 나뉘고, 구간 사이 게이팅 룰이 낮은 PL 에서 하위 구간을 건너뛴다.

---

## 5. 검증 (테스트 하네스)

```
tests/
├── lib.sh · verify.sh · run-all.sh   # 범용 하네스
├── cases.tsv                         # 룰 id별 공격 예제
├── <rule-id>.sh                      # 룰 id별 개별 실행
└── (로그: ../../../logs/local_test/<파일명>/)
```

```bash
cd rules/REQUEST-933-APPLICATION-ATTACK-PHP/tests
./run-all.sh      # 전체
./<rule-id>.sh   # 개별
```

로그: `logs/local_test/REQUEST-933-APPLICATION-ATTACK-PHP/`

---

## 6. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 생성 도구: `tools/gen_rule_docs.py`, `tools/make_harness.sh`
- 룰 원본: `coreruleset/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf`
