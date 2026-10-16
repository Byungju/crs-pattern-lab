# RESPONSE-980-CORRELATION.conf — 쉽게 읽는 분석

> 이 문서는 `RESPONSE-980-CORRELATION.conf` 룰을 "기초 → 룰 → 공격 예제 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/RESPONSE-980-CORRELATION.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터, 3/4=응답, 5=로깅.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝(또는 phase 4 끝)에 `949110`/`959110` 이 임계값을 넘으면 차단.
- **paranoia level(PL)**: 1~4. 구간 사이 게이팅 룰(`…011`~`…018`)이 있다.

> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> 요청/응답 단계의 어노말리 점수를 상관분석하고 통계를 남긴다.

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [980099](980099.md) | 5 | - | - | (helper) |
| [980041](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980042](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980043](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980044](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980045](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980046](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980047](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980048](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980049](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980050](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980051](../../modsecurity/paranoia-gating.md) | 5 | - | - | (게이팅) PL 구간 제어 |
| [980170](980170.md) | 5 | - | - | Anomaly Scores: \ |
| [980011](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [980012](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [980013](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [980014](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [980015](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [980016](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [980017](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [980018](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |

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
cd rules/RESPONSE-980-CORRELATION/tests
./run-all.sh      # 전체
./<rule-id>.sh   # 개별
```

로그: `logs/local_test/RESPONSE-980-CORRELATION/`

---

## 6. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 생성 도구: `tools/gen_rule_docs.py`, `tools/make_harness.sh`
- 룰 원본: `coreruleset/rules/RESPONSE-980-CORRELATION.conf`
