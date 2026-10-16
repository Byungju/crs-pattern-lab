# REQUEST-949-BLOCKING-EVALUATION.conf — 쉽게 읽는 분석

> 이 문서는 `REQUEST-949-BLOCKING-EVALUATION.conf` 룰을 "기초 → 룰 → 공격 예제 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터, 3/4=응답, 5=로깅.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝(또는 phase 4 끝)에 `949110`/`959110` 이 임계값을 넘으면 차단.
- **paranoia level(PL)**: 1~4. 구간 사이 게이팅 룰(`…011`~`…018`)이 있다.

> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> 요청(인바운드) 점수가 임계값을 넘으면 403으로 차단한다.

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [949052](949052.md) | 1 | - | - | (helper) |
| [949152](949152.md) | 1 | - | - | (helper) |
| [949053](949053.md) | 1 | - | - | (helper) |
| [949153](949153.md) | 1 | - | - | (helper) |
| [949054](949054.md) | 1 | - | - | (helper) |
| [949154](949154.md) | 1 | - | - | (helper) |
| [949055](949055.md) | 1 | - | - | (helper) |
| [949155](949155.md) | 1 | - | - | (helper) |
| [949059](949059.md) | 2 | - | - | (helper) |
| [949159](949159.md) | 2 | - | - | (helper) |
| [949060](949060.md) | 2 | - | - | (helper) |
| [949160](949160.md) | 2 | - | - | (helper) |
| [949061](949061.md) | 2 | - | - | (helper) |
| [949161](949161.md) | 2 | - | - | (helper) |
| [949062](949062.md) | 2 | - | - | (helper) |
| [949162](949162.md) | 2 | - | - | (helper) |
| [949063](949063.md) | 2 | - | - | (helper) |
| [949163](949163.md) | 2 | - | - | (helper) |
| [949111](949111.md) | 1 | - | - | Inbound Anomaly Score Exceeded in phase 1 (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE}) |
| [949110](949110.md) | 2 | - | - | Inbound Anomaly Score Exceeded (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE}) |
| [949011](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [949012](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [949013](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [949014](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [949015](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [949016](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [949017](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [949018](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |

---

## 3. 공격 예제 및 실측

| ID | 공격 예제(요청) | HTTP |
|----|------------------|------|
| [949110](949110.md) | `/?id=1%27%20OR%20%271%27%3D%271` | **403** |

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
cd rules/REQUEST-949-BLOCKING-EVALUATION/tests
./run-all.sh      # 전체
./<rule-id>.sh   # 개별
```

로그: `logs/local_test/REQUEST-949-BLOCKING-EVALUATION/`

---

## 6. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 생성 도구: `tools/gen_rule_docs.py`, `tools/make_harness.sh`
- 룰 원본: `coreruleset/rules/REQUEST-949-BLOCKING-EVALUATION.conf`
