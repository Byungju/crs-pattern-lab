# REQUEST-941-APPLICATION-ATTACK-XSS.conf — 쉽게 읽는 분석

> 이 문서는 `REQUEST-941-APPLICATION-ATTACK-XSS.conf` 룰을 "기초 → 룰 → 공격 예제 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터, 3/4=응답, 5=로깅.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝(또는 phase 4 끝)에 `949110`/`959110` 이 임계값을 넘으면 차단.
- **paranoia level(PL)**: 1~4. 구간 사이 게이팅 룰(`…011`~`…018`)이 있다.

> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> XSS(크로스사이트 스크립팅) 공격을 탐지한다.

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [941011](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [941012](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [941010](941010.md) | 1 | - | - | (helper) |
| [941100](941100.md) | 2 | 1 | CRITICAL | XSS Attack Detected via libinjection |
| [941110](941110.md) | 2 | 1 | CRITICAL | XSS Filter - Category 1: Script Tag Vector |
| [941120](941120.md) | 2 | 1 | CRITICAL | XSS Filter - Category 2: Event Handler Vector |
| [941130](941130.md) | 2 | 1 | CRITICAL | XSS Filter - Category 3: Attribute Vector |
| [941140](941140.md) | 2 | 1 | CRITICAL | XSS Filter - Category 4: Javascript URI Vector |
| [941160](941160.md) | 2 | 1 | CRITICAL | NoScript XSS InjectionChecker: HTML Injection |
| [941170](941170.md) | 2 | 1 | CRITICAL | NoScript XSS InjectionChecker: Attribute Injection |
| [941180](941180.md) | 2 | 1 | CRITICAL | Node-Validator Deny List Keywords |
| [941190](941190.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941200](941200.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941210](941210.md) | 2 | 1 | CRITICAL | Javascript Word Detected |
| [941220](941220.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941230](941230.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941240](941240.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941250](941250.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941260](941260.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941270](941270.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941280](941280.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941290](941290.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941300](941300.md) | 2 | 1 | CRITICAL | IE XSS Filters - Attack Detected |
| [941310](941310.md) | 2 | 1 | CRITICAL | US-ASCII Malformed Encoding XSS Filter - Attack Detected |
| [941350](941350.md) | 2 | 1 | CRITICAL | UTF-7 Encoding IE XSS - Attack Detected |
| [941360](941360.md) | 2 | 1 | CRITICAL | JSFuck / Hieroglyphy obfuscation detected |
| [941370](941370.md) | 2 | 1 | CRITICAL | JavaScript global variable found |
| [941390](941390.md) | 2 | 1 | CRITICAL | Javascript method detected |
| [941400](941400.md) | 2 | 1 | CRITICAL | XSS JavaScript function without parentheses |
| [941013](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [941014](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [941101](941101.md) | 1 | 2 | CRITICAL | XSS Attack Detected via libinjection |
| [941150](941150.md) | 2 | 2 | CRITICAL | XSS Filter - Category 5: Disallowed HTML Attributes |
| [941181](941181.md) | 2 | 2 | CRITICAL | Node-Validator Deny List Keywords |
| [941320](941320.md) | 2 | 2 | CRITICAL | Possible XSS Attack Detected - HTML Tag Handler |
| [941330](941330.md) | 2 | 2 | CRITICAL | IE XSS Filters - Attack Detected |
| [941340](941340.md) | 2 | 2 | CRITICAL | IE XSS Filters - Attack Detected |
| [941380](941380.md) | 2 | 2 | CRITICAL | AngularJS client side template injection detected |
| [941015](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [941016](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [941017](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [941018](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |

---

## 3. 공격 예제 및 실측

| ID | 공격 예제(요청) | HTTP |
|----|------------------|------|
| [941100](941100.md) | `/?x=<script>alert(1)</script>` | **403** |
| [941110](941110.md) | `/?x=<script>alert(1)</script>` | **403** |
| [941160](941160.md) | `/?x=<script>alert(1)</script>` | **403** |
| [941320](941320.md) | `/?x=<script>alert(1)</script>` | **403** |
| [941390](941390.md) | `/?x=<script>alert(1)</script>` | **403** |
| [941170](941170.md) | `/?x=javascript:alert(1)` | **403** |
| [941210](941210.md) | `/?x=javascript:alert(1)` | **403** |
| [941120](941120.md) | `/?x=<svg/onload=alert(1)>` | **403** |

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
cd rules/REQUEST-941-APPLICATION-ATTACK-XSS/tests
./run-all.sh      # 전체
./<rule-id>.sh   # 개별
```

로그: `logs/local_test/REQUEST-941-APPLICATION-ATTACK-XSS/`

---

## 6. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 생성 도구: `tools/gen_rule_docs.py`, `tools/make_harness.sh`
- 룰 원본: `coreruleset/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf`
