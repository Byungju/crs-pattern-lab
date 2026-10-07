# CRS 점수(스코어)와 Paranoia Level — 연결 이해

> 이 문서는 "룰이 매칭되면 왜 403이 되는가", 그리고 "**점수 5는 어디서 나오는가**",
> "**paranoia level 게이트와 탐지 룰은 무슨 관계인가**"를 한 줄기로 연결해 설명한다.
> 룰 문서(`<id>.md`)를 읽다가 막히면 여기로 돌아오면 된다.

---

## 0. 한눈에 보는 핵심

```
[게이트]  tx.detection_paranoia_level  ── "이 PL 이하는 실행하라" (913100 실행 여부)
   │
   ▼
[탐지 룰]  913100 매칭 → tx.inbound_anomaly_score_pl1 += tx.critical_anomaly_score(=5)
   │                                    ☝ 점수 5 는 901140 이 넣은 기본값
   ▼
[합산]    blocking_paranoia_level >= 1 이면
          949052: tx.blocking_inbound_anomaly_score += tx.inbound_anomaly_score_pl1
   │
   ▼
[차단]    tx.inbound_anomaly_score_threshold(=5) 이상이면
          949110: deny → HTTP 403
```

즉 **913100은 점수만 쌓고, 실제 403은 949110이 판단**한다. 점수 5는 913100에 하드코딩된 게 아니라
**severity(CRITICAL)에 매핑된 `tx.critical_anomaly_score`(=5)** 이다.

---

## 1. 등장하는 변수와 기본값

| 변수 | 기본값 | 값을 넣는 룰 | 사용자 설정(crs-setup) |
|------|--------|--------------|------------------------|
| `tx.blocking_paranoia_level` | 1 | [901120](../rules/REQUEST-901-INITIALIZATION/901120.md) | `900000` |
| `tx.detection_paranoia_level` | = blocking | [901125](../rules/REQUEST-901-INITIALIZATION/901125.md) | `900001` |
| `tx.critical_anomaly_score` | 5 | [901140](../rules/REQUEST-901-INITIALIZATION/901140.md) | `900100` |
| `tx.error_anomaly_score` | 4 | [901141](../rules/REQUEST-901-INITIALIZATION/901141.md) | `900100` |
| `tx.warning_anomaly_score` | 3 | [901142](../rules/REQUEST-901-INITIALIZATION/901142.md) | `900100` |
| `tx.notice_anomaly_score` | 2 | [901143](../rules/REQUEST-901-INITIALIZATION/901143.md) | `900100` |
| `tx.inbound_anomaly_score_threshold` | 5 | [901100](../rules/REQUEST-901-INITIALIZATION/901100.md) | `900110` |
| `tx.outbound_anomaly_score_threshold` | 4 | [901110](../rules/REQUEST-901-INITIALIZATION/901110.md) | `900110` |
| `tx.inbound_anomaly_score_pl1` ~ `pl4` | 0 | [901200](../rules/REQUEST-901-INITIALIZATION/901200.md) | - |
| `tx.blocking_inbound_anomaly_score` | 0 | 901200 → 949052~ 합산 | - |

> 모두 `tx.` 변수라 **요청마다 새로** 초기화된다.

---

## 2. (게이트) detection_paranoia_level — "탐지 룰이 실행되는 범위"

> 게이트 룰의 상세/정본: [paranoia-gating.md](paranoia-gating.md)

- CRS 파일은 룰을 **PL1 / PL2 / PL3 / PL4 구간**으로 나눈다.
- 각 구간 앞에 게이팅 룰이 있다: `SecRule TX:DETECTION_PARANOIA_LEVEL "@lt N" ... skipAfter:END`.
  → **현재 detection PL이 N 미만이면 그 구간부터 끝까지 건너뛴다.**
- 예) `REQUEST-913` 구조:

```
913011/913012  (@lt 1)  ── 게이트
── PL1 구간 ──
913100         ← 스캐너 탐지 룰 (여기에 있음)
913013/913014  (@lt 2)  ── 게이트
── PL2 구간 ── (비어 있음)
913015/913016  (@lt 3)  ── 게이트
── PL3 구간 ── (비어 있음)
913017/913018  (@lt 4)  ── 게이트
── PL4 구간 ── (비어 있음)
SecMarker "END-REQUEST-913-SCANNER-DETECTION"
```

- **기본값 detection PL = 1** 이므로 913100(PL1)은 실행되고, `913013` 이상은 `END`로 점프한다.
- 만약 detection PL = 0 이면 `913011`이 `END`로 점프해 **913100도 실행되지 않는다.**

> 정리: `DETECTION_PARANOIA_LEVEL` 은 **"913100을 실행할지 말지"를 정하는 스위치**다.

---

## 3. (점수) severity → `tx.<sev>_anomaly_score` → `plN`

탐지 룰은 매칭 시 자기 PL 위치에 맞는 스코어 버킷에 점수를 더한다.

```
# 913100 (PL1 룰, severity CRITICAL)
setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'
                                     └─ 901140 이 5 로 설정한 값
```

- 룰에 적힌 `severity:'CRITICAL'` 은 "이 룰은 critical 등급"이라는 표시이고,
  실제 점수는 **`tx.critical_anomaly_score`(기본 5)** 를 사용한다.
- 따라서 "**점수 5**"의 출처는 `901140`(또는 사용자가 `crs-setup.conf` `900100` 으로 바꾼 값)이다.
- severity ↔ 변수 매핑: CRITICAL→5, ERROR→4, WARNING→3, NOTICE→2.
- `plN` 의 N 은 그 룰이 속한 구간(PL)을 뜻한다(913100은 PL1 → `pl1`).

---

## 4. (합산/차단) blocking_paranoia_level 과 949

점수를 모아 실제 차단하는 곳은 `REQUEST-949-BLOCKING-EVALUATION.conf` 다.

```
# 949052 (phase1)
SecRule TX:BLOCKING_PARANOIA_LEVEL "@ge 1"
    → setvar:'tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}'

# 949110
SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}"
    → deny (403)
```

- `blocking_paranoia_level` 은 **"점수를 차단 계산에 포함할 최대 PL"** 이다.
  - blocking PL=1 이면 `pl1` 점수만 차단 계산에 포함(949052).
  - blocking PL=2 이면 `pl1+pl2` 포함(949053까지), …
- detection PL > blocking PL 로 두면 상위 PL 룰은 **실행은 되지만**(detection 버킷에 쌓임)
  차단 계산에는 반영되지 않는다(관찰용).
- 최종적으로 누적 `blocking_inbound_anomaly_score >= tx.inbound_anomaly_score_threshold` 이면
  **949110 이 403** 을 반환한다.

---

## 5. 913100 을 예로 끝까지 따라가기

```
1) 901125 가 tx.detection_paranoia_level = 1 로 세팅
2) 게이트 913011(@lt1) 은 1<1 이 false → 통과
3) 913100 실행: UA가 스캐너 목록에 매칭
      → tx.inbound_anomaly_score_pl1 += tx.critical_anomaly_score(5)
4) 게이트 913013(@lt2) 은 1<2 가 true → END 로 점프 (PL2~4 skip)
5) 949052: blocking_pl(1) >= 1 → blocking_inbound_anomaly_score += pl1(5)
6) 949110: 5 >= tx.inbound_anomaly_score_threshold(5) → deny → HTTP 403
```

---

## 6. "왜 룰 파일을 보면 이 연결이 안 보이나"

- 탐지 룰 파일(913100 등)은 **점수만 쌓고** 차단하지 않는다(`block` 은 표시일 뿐).
- 실제 차단은 **다른 파일(REQUEST-949 / RESPONSE-959)** 에 있다.
- PL 게이트 룰은 **탐지가 아니라 제어 흐름**이라 별도로 보인다.
- 점수 값은 룰 본문이 아니라 **`tx.<sev>_anomaly_score` 변수(901140 등)** 에 있다.

이 4가지를 기억하면 룰 파일이 훨씬 잘 연결된다.

---

## 7. 참고

- 실행 모델(phase): [execution-model.md](execution-model.md)
- crs-setup 정책 변수: [base-rules/crs-setup-conf.md](base-rules/crs-setup-conf.md)
- modsecurity.conf 엔진 설정: [base-rules/modsecurity-conf.md](base-rules/modsecurity-conf.md)
