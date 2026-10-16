# REQUEST-934-APPLICATION-ATTACK-GENERIC.conf — 쉽게 읽는 분석

> 이 문서는 `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` 룰을 "기초 → 룰 → 공격 예제 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터, 3/4=응답, 5=로깅.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝(또는 phase 4 끝)에 `949110`/`959110` 이 임계값을 넘으면 차단.
- **paranoia level(PL)**: 1~4. 구간 사이 게이팅 룰(`…011`~`…018`)이 있다.

> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> 여러 공격 유형에 걸친 제네릭(휴리스틱) 공격을 탐지한다.

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [934011](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [934012](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [934100](934100.md) | 2 | 1 | CRITICAL | Node.js Injection Attack 1/2 |
| [934110](934110.md) | 2 | 1 | CRITICAL | Possible Server Side Request Forgery (SSRF) Attack: Cloud provider metadata URL in Parameter |
| [934190](934190.md) | 2 | 1 | CRITICAL | Possible Server Side Request Forgery (SSRF) Attack: Scheme-less localhost or internal hostname detected |
| [934130](934130.md) | 2 | 1 | CRITICAL | JavaScript Prototype Pollution |
| [934150](934150.md) | 2 | 1 | CRITICAL | Ruby Injection Attack |
| [934160](934160.md) | 2 | 1 | CRITICAL | Node.js DoS attack |
| [934170](934170.md) | 2 | 1 | CRITICAL | PHP data scheme attack |
| [934200](934200.md) | 2 | 1 | CRITICAL | Server-Side Template Injection (SSTI) Attack |
| [934013](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [934014](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [934101](934101.md) | 2 | 2 | CRITICAL | Node.js Injection Attack 2/2 |
| [934120](934120.md) | 2 | 2 | CRITICAL | Possible Server Side Request Forgery (SSRF) Attack: URL Parameter using IP Address |
| [934140](934140.md) | 2 | 2 | CRITICAL | Perl Injection Attack |
| [934180](934180.md) | 2 | 2 | CRITICAL | SSTI Attack |
| [934220](934220.md) | 2 | 2 | CRITICAL | ORM Lookup Operator Injection via Nested Traversal |
| [934015](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [934016](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [934210](934210.md) | 2 | 3 | CRITICAL | ORM Lookup Operator Injection |
| [934017](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [934018](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |

---

## 3. 공격 예제 및 실측

- 구현된 공격 예제는 `tests/cases.tsv` 참고 (현재 없음/SKIP 중심).

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
cd rules/REQUEST-934-APPLICATION-ATTACK-GENERIC/tests
./run-all.sh      # 전체
./<rule-id>.sh   # 개별
```

로그: `logs/local_test/REQUEST-934-APPLICATION-ATTACK-GENERIC/`

---

## 6. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 생성 도구: `tools/gen_rule_docs.py`, `tools/make_harness.sh`
- 룰 원본: `coreruleset/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf`
