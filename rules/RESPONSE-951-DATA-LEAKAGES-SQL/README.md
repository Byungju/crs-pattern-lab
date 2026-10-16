# RESPONSE-951-DATA-LEAKAGES-SQL.conf — 쉽게 읽는 분석

> 이 문서는 `RESPONSE-951-DATA-LEAKAGES-SQL.conf` 룰을 "기초 → 룰 → 공격 예제 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터, 3/4=응답, 5=로깅.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝(또는 phase 4 끝)에 `949110`/`959110` 이 임계값을 넘으면 차단.
- **paranoia level(PL)**: 1~4. 구간 사이 게이팅 룰(`…011`~`…018`)이 있다.

> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> 응답에서 SQL 에러/정보 유출을 탐지한다.

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [951010](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |
| [951011](../../modsecurity/paranoia-gating.md) | 3 | - | - | (게이팅) PL 구간 제어 |
| [951012](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |
| [951100](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |
| [951110](951110.md) | 4 | 1 | CRITICAL | Microsoft Access SQL Information Leakage |
| [951120](951120.md) | 4 | 1 | CRITICAL | Oracle SQL Information Leakage |
| [951130](951130.md) | 4 | 1 | CRITICAL | DB2 SQL Information Leakage |
| [951140](951140.md) | 4 | 1 | CRITICAL | EMC SQL Information Leakage |
| [951150](951150.md) | 4 | 1 | CRITICAL | firebird SQL Information Leakage |
| [951160](951160.md) | 4 | 1 | CRITICAL | Frontbase SQL Information Leakage |
| [951170](951170.md) | 4 | 1 | CRITICAL | hsqldb SQL Information Leakage |
| [951180](951180.md) | 4 | 1 | CRITICAL | informix SQL Information Leakage |
| [951190](951190.md) | 4 | 1 | CRITICAL | ingres SQL Information Leakage |
| [951200](951200.md) | 4 | 1 | CRITICAL | interbase SQL Information Leakage |
| [951210](951210.md) | 4 | 1 | CRITICAL | maxDB SQL Information Leakage |
| [951220](951220.md) | 4 | 1 | CRITICAL | mssql SQL Information Leakage |
| [951230](951230.md) | 4 | 1 | CRITICAL | mysql SQL Information Leakage |
| [951240](951240.md) | 4 | 1 | CRITICAL | postgres SQL Information Leakage |
| [951250](951250.md) | 4 | 1 | CRITICAL | sqlite SQL Information Leakage |
| [951260](951260.md) | 4 | 1 | CRITICAL | Sybase SQL Information Leakage |
| [951013](../../modsecurity/paranoia-gating.md) | 3 | - | - | (게이팅) PL 구간 제어 |
| [951014](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |
| [951015](../../modsecurity/paranoia-gating.md) | 3 | - | - | (게이팅) PL 구간 제어 |
| [951016](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |
| [951017](../../modsecurity/paranoia-gating.md) | 3 | - | - | (게이팅) PL 구간 제어 |
| [951018](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |

---

## 3. 공격 예제 및 실측

| ID | 공격 예제(요청) | HTTP |
|----|------------------|------|
| [951230](951230.md) | `/leak_sql.html` | 200대 |
| [951220](951220.md) | `/leak_iis.html` | 200대 |

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
cd rules/RESPONSE-951-DATA-LEAKAGES-SQL/tests
./run-all.sh      # 전체
./<rule-id>.sh   # 개별
```

로그: `logs/local_test/RESPONSE-951-DATA-LEAKAGES-SQL/`

---

## 6. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 생성 도구: `tools/gen_rule_docs.py`, `tools/make_harness.sh`
- 룰 원본: `coreruleset/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf`
