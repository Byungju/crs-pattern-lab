# REQUEST-942-APPLICATION-ATTACK-SQLI.conf — 쉽게 읽는 분석

> 이 문서는 `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` 룰을 "기초 → 룰 → 공격 예제 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터, 3/4=응답, 5=로깅.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝(또는 phase 4 끝)에 `949110`/`959110` 이 임계값을 넘으면 차단.
- **paranoia level(PL)**: 1~4. 구간 사이 게이팅 룰(`…011`~`…018`)이 있다.

> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> SQL 인젝션 공격을 탐지한다.

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [942011](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [942012](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [942100](942100.md) | 2 | 1 | CRITICAL | SQL Injection Attack Detected via libinjection |
| [942140](942140.md) | 2 | 1 | CRITICAL | SQL Injection Attack: Common DB Names Detected |
| [942151](942151.md) | 2 | 1 | CRITICAL | SQL Injection Attack: SQL function name detected |
| [942160](942160.md) | 2 | 1 | CRITICAL | Detects blind sqli tests using sleep() or benchmark() |
| [942170](942170.md) | 2 | 1 | CRITICAL | Detects SQL benchmark and sleep injection attempts including conditional queries |
| [942190](942190.md) | 2 | 1 | CRITICAL | Detects SQL code execution and information gathering attempts |
| [942220](942220.md) | 2 | 1 | CRITICAL | Looking for integer overflow attacks, these are taken from skipfish, except 2.2.2250738585072011e-308 is the \"magic number\" crash |
| [942230](942230.md) | 2 | 1 | CRITICAL | Detects conditional SQL injection attempts |
| [942240](942240.md) | 2 | 1 | CRITICAL | Detects MySQL charset switch and MSSQL DoS attempts |
| [942250](942250.md) | 2 | 1 | CRITICAL | Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections |
| [942270](942270.md) | 2 | 1 | CRITICAL | Looking for basic sql injection. Common attack string for mysql, oracle and others |
| [942280](942280.md) | 2 | 1 | CRITICAL | Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts |
| [942290](942290.md) | 2 | 1 | CRITICAL | Finds basic MongoDB SQL injection attempts |
| [942320](942320.md) | 2 | 1 | CRITICAL | Detects MySQL and PostgreSQL stored procedure/function injections |
| [942350](942350.md) | 2 | 1 | CRITICAL | Detects MySQL UDF injection and other data/structure manipulation attempts |
| [942360](942360.md) | 2 | 1 | CRITICAL | Detects concatenated basic SQL injection and SQLLFI attempts |
| [942500](942500.md) | 2 | 1 | CRITICAL | MySQL in-line comment detected |
| [942540](942540.md) | 2 | 1 | CRITICAL | SQL Authentication bypass (split query) |
| [942560](942560.md) | 2 | 1 | CRITICAL | MySQL Scientific Notation payload detected |
| [942550](942550.md) | 2 | 1 | CRITICAL | JSON-Based SQL Injection |
| [942013](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [942014](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [942120](942120.md) | 2 | 2 | CRITICAL | SQL Injection Attack: SQL Operator Detected |
| [942130](942130.md) | 2 | 2 | CRITICAL | SQL Injection Attack: SQL Boolean-based attack detected |
| [942131](942131.md) | 2 | 2 | CRITICAL | SQL Injection Attack: SQL Boolean-based attack detected |
| [942150](942150.md) | 2 | 2 | CRITICAL | SQL Injection Attack: SQL function name detected |
| [942180](942180.md) | 2 | 2 | CRITICAL | Detects basic SQL authentication bypass attempts 1/3 |
| [942200](942200.md) | 2 | 2 | CRITICAL | Detects MySQL comment-/space-obfuscated injections and backtick termination |
| [942210](942210.md) | 2 | 2 | CRITICAL | Detects chained SQL injection attempts 1/2 |
| [942260](942260.md) | 2 | 2 | CRITICAL | Detects basic SQL authentication bypass attempts 2/3 |
| [942300](942300.md) | 2 | 2 | CRITICAL | Detects MySQL comments, conditions and ch(a)r injections |
| [942310](942310.md) | 2 | 2 | CRITICAL | Detects chained SQL injection attempts 2/2 |
| [942330](942330.md) | 2 | 2 | CRITICAL | Detects classic SQL injection probings 1/3 |
| [942340](942340.md) | 2 | 2 | CRITICAL | Detects basic SQL authentication bypass attempts 3/3 |
| [942361](942361.md) | 2 | 2 | CRITICAL | Detects basic SQL injection based on keyword alter or union |
| [942362](942362.md) | 2 | 2 | CRITICAL | Detects concatenated basic SQL injection and SQLLFI attempts |
| [942370](942370.md) | 2 | 2 | CRITICAL | Detects classic SQL injection probings 2/3 |
| [942380](942380.md) | 2 | 2 | CRITICAL | SQL Injection Attack |
| [942390](942390.md) | 2 | 2 | CRITICAL | SQL Injection Attack using (X)OR |
| [942400](942400.md) | 2 | 2 | CRITICAL | SQL Injection Attack |
| [942410](942410.md) | 2 | 2 | CRITICAL | SQL Injection Attack |
| [942470](942470.md) | 2 | 2 | CRITICAL | SQL Injection Attack |
| [942480](942480.md) | 2 | 2 | CRITICAL | SQL Injection Attack |
| [942430](942430.md) | 2 | 2 | WARNING | Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12) |
| [942440](942440.md) | 2 | 2 | CRITICAL | SQL Comment Sequence Detected |
| [942450](942450.md) | 2 | 2 | CRITICAL | SQL Bin or Hex Encoding Identified |
| [942510](942510.md) | 2 | 2 | CRITICAL | SQLi bypass attempt by ticks or backticks detected |
| [942520](942520.md) | 2 | 2 | CRITICAL | Detects basic SQL authentication bypass attempts 4.0/4 |
| [942521](942521.md) | 2 | 2 | CRITICAL | Detects basic SQL authentication bypass attempts 4.1/4 |
| [942522](942522.md) | 2 | 2 | CRITICAL | Detects basic SQL authentication bypass attempts 4.1/4 |
| [942101](942101.md) | 1 | 2 | CRITICAL | SQL Injection Attack Detected via libinjection |
| [942152](942152.md) | 1 | 2 | CRITICAL | SQL Injection Attack: SQL function name detected |
| [942321](942321.md) | 1 | 2 | CRITICAL | Detects MySQL and PostgreSQL stored procedure/function injections |
| [942015](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [942016](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [942251](942251.md) | 2 | 3 | CRITICAL | Detects HAVING injections |
| [942490](942490.md) | 2 | 3 | CRITICAL | Detects classic SQL injection probings 3/3 |
| [942420](942420.md) | 1 | 3 | WARNING | Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (8) |
| [942431](942431.md) | 2 | 3 | WARNING | Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6) |
| [942460](942460.md) | 2 | 3 | WARNING | Meta-Character Anomaly Detection Alert - Repetitive Non-Word Characters |
| [942511](942511.md) | 2 | 3 | CRITICAL | SQLi bypass attempt by ticks detected |
| [942530](942530.md) | 2 | 3 | CRITICAL | SQLi query termination detected |
| [942017](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [942018](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [942421](942421.md) | 1 | 4 | WARNING | Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (3) |
| [942432](942432.md) | 2 | 4 | WARNING | Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2) |

---

## 3. 공격 예제 및 실측

| ID | 공격 예제(요청) | HTTP |
|----|------------------|------|
| [942100](942100.md) | `/?id=1%27%20OR%20%271%27%3D%271` | **403** |
| [942130](942130.md) | `/?id=1%27%20OR%20%271%27%3D%271` | **403** |
| [942180](942180.md) | `/?id=1%27%20OR%20%271%27%3D%271` | **403** |
| [942330](942330.md) | `/?id=1%27%20OR%20%271%27%3D%271` | **403** |
| [942370](942370.md) | `/?id=1%27%20OR%20%271%27%3D%271` | **403** |
| [942390](942390.md) | `/?id=1%27%20OR%20%271%27%3D%271` | **403** |
| [942432](942432.md) | `/?id=1%27%20OR%20%271%27%3D%271` | **403** |
| [942511](942511.md) | `/?id=1%27%20OR%20%271%27%3D%271` | **403** |
| [942520](942520.md) | `/?id=1%27%20OR%20%271%27%3D%271` | **403** |

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
cd rules/REQUEST-942-APPLICATION-ATTACK-SQLI/tests
./run-all.sh      # 전체
./<rule-id>.sh   # 개별
```

로그: `logs/local_test/REQUEST-942-APPLICATION-ATTACK-SQLI/`

---

## 6. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 생성 도구: `tools/gen_rule_docs.py`, `tools/make_harness.sh`
- 룰 원본: `coreruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf`
