# REQUEST-932-APPLICATION-ATTACK-RCE.conf — 쉽게 읽는 분석

> 이 문서는 `REQUEST-932-APPLICATION-ATTACK-RCE.conf` 룰을 "기초 → 룰 → 공격 예제 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터, 3/4=응답, 5=로깅.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝(또는 phase 4 끝)에 `949110`/`959110` 이 임계값을 넘으면 차단.
- **paranoia level(PL)**: 1~4. 구간 사이 게이팅 룰(`…011`~`…018`)이 있다.

> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> 원격 명령 실행(RCE) 공격을 탐지한다.

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [932011](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [932012](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [932230](932230.md) | 2 | 1 | CRITICAL | Remote Command Execution: Unix Command Injection (2-3 chars) |
| [932235](932235.md) | 2 | 1 | CRITICAL | Remote Command Execution: Unix Command Injection (command without evasion) |
| [932120](932120.md) | 2 | 1 | CRITICAL | Remote Command Execution: Windows PowerShell Command Found |
| [932125](932125.md) | 2 | 1 | CRITICAL | Remote Command Execution: Windows Powershell Alias Command Injection |
| [932130](932130.md) | 2 | 1 | CRITICAL | Remote Command Execution: Unix Shell Expression Found |
| [932140](932140.md) | 2 | 1 | CRITICAL | Remote Command Execution: Windows FOR/IF Command Found |
| [932270](932270.md) | 2 | 1 | CRITICAL | Remote Command Execution: Unix Shell Expression Found |
| [932280](932280.md) | 2 | 1 | CRITICAL | Remote Command Execution: Brace Expansion Found |
| [932250](932250.md) | 2 | 1 | CRITICAL | Remote Command Execution: Direct Unix Command Execution |
| [932260](932260.md) | 2 | 1 | CRITICAL | Remote Command Execution: Direct Unix Command Execution |
| [932340](932340.md) | 2 | 1 | CRITICAL | Remote Command Execution: Direct Unix Command Execution (No Arguments) |
| [932330](932330.md) | 2 | 1 | CRITICAL | Remote Command Execution: Unix shell history invocation |
| [932160](932160.md) | 2 | 1 | CRITICAL | Remote Command Execution: Unix Shell Code Found |
| [932170](932170.md) | 1 | 1 | CRITICAL | Remote Command Execution: Shellshock (CVE-2014-6271) |
| [932171](932171.md) | 2 | 1 | CRITICAL | Remote Command Execution: Shellshock (CVE-2014-6271) |
| [932175](932175.md) | 2 | 1 | CRITICAL | Remote Command Execution: Unix shell alias invocation |
| [932180](932180.md) | 2 | 1 | CRITICAL | Restricted File Upload Attempt |
| [932370](932370.md) | 2 | 1 | CRITICAL | Remote Command Execution: Windows Command Injection |
| [932380](932380.md) | 2 | 1 | CRITICAL | Remote Command Execution: Windows Command Injection |
| [932013](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [932014](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [932371](932371.md) | 2 | 2 | CRITICAL | Remote Command Execution: Windows Command Injection |
| [932231](932231.md) | 2 | 2 | CRITICAL | Remote Command Execution: Unix Command Injection |
| [932131](932131.md) | 1 | 2 | CRITICAL | Remote Command Execution: Unix Shell Expression Found |
| [932200](932200.md) | 2 | 2 | CRITICAL | RCE Bypass Technique |
| [932205](932205.md) | 1 | 2 | CRITICAL | RCE Bypass Technique |
| [932206](932206.md) | 1 | 2 | CRITICAL | RCE Bypass Technique |
| [932207](932207.md) | 1 | 2 | CRITICAL | RCE Bypass Technique |
| [932220](932220.md) | 2 | 2 | CRITICAL | Remote Command Execution: Unix Command Injection with pipe |
| [932240](932240.md) | 2 | 2 | CRITICAL | Remote Command Execution: Unix Command Injection evasion attempt detected |
| [932281](932281.md) | 2 | 2 | CRITICAL | Remote Command Execution: Brace Expansion Found |
| [932210](932210.md) | 2 | 2 | CRITICAL | Remote Command Execution: SQLite System Command Execution |
| [932271](932271.md) | 2 | 2 | CRITICAL | Remote Command Execution: Unix Shell Expression Found |
| [932300](932300.md) | 2 | 2 | CRITICAL | Remote Command Execution: SMTP Command Execution |
| [932310](932310.md) | 2 | 2 | CRITICAL | Remote Command Execution: IMAP Command Execution |
| [932320](932320.md) | 2 | 2 | CRITICAL | Remote Command Execution: POP3 Command Execution |
| [932236](932236.md) | 2 | 2 | CRITICAL | Remote Command Execution: Unix Command Injection (command without evasion) |
| [932239](932239.md) | 1 | 2 | CRITICAL | Remote Command Execution: Unix Command Injection found in user-agent or referer header |
| [932161](932161.md) | 1 | 2 | CRITICAL | Remote Command Execution: Unix Shell Code Found in REQUEST_HEADERS |
| [932390](932390.md) | 2 | 2 | CRITICAL | Remote Command Execution: Shell Fork Bomb |
| [932015](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [932016](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [932232](932232.md) | 2 | 3 | CRITICAL | Remote Command Execution: Unix Command Injection |
| [932237](932237.md) | 1 | 3 | CRITICAL | Remote Command Execution: Unix Shell Code Found in REQUEST_HEADERS |
| [932238](932238.md) | 2 | 3 | CRITICAL | Remote Command Execution: Unix Shell Code Found in REQUEST_HEADERS |
| [932290](932290.md) | 2 | 3 | CRITICAL | Remote Command Execution: Quote evasion Found |
| [932190](932190.md) | 2 | 3 | CRITICAL | Remote Command Execution: Wildcard bypass technique attempt |
| [932350](932350.md) | 2 | 3 | CRITICAL | Remote Command Execution: Direct Unix Command Execution (No Arguments) |
| [932301](932301.md) | 2 | 3 | CRITICAL | Remote Command Execution: SMTP Command Execution |
| [932311](932311.md) | 2 | 3 | CRITICAL | Remote Command Execution: IMAP Command Execution |
| [932321](932321.md) | 2 | 3 | CRITICAL | Remote Command Execution: POP3 Command Execution |
| [932331](932331.md) | 2 | 3 | CRITICAL | Remote Command Execution: Unix shell history invocation |
| [932017](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [932018](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |

---

## 3. 공격 예제 및 실측

| ID | 공격 예제(요청) | HTTP |
|----|------------------|------|
| [932350](932350.md) | `/?x=|id` | **403** |
| [932160](932160.md) | `/?x=%3Bcat%20/etc/passwd` | **403** |
| [932236](932236.md) | `/?x=%3Bcat%20/etc/passwd` | **403** |
| [932130](932130.md) | `/?x=$(id)` | **403** |

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
cd rules/REQUEST-932-APPLICATION-ATTACK-RCE/tests
./run-all.sh      # 전체
./<rule-id>.sh   # 개별
```

로그: `logs/local_test/REQUEST-932-APPLICATION-ATTACK-RCE/`

---

## 6. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 생성 도구: `tools/gen_rule_docs.py`, `tools/make_harness.sh`
- 룰 원본: `coreruleset/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf`
