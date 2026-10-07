# Paranoia Level 게이팅(PL 게이트) — 정본

> CRS 룰 파일마다 반복 등장하는 `skipAfter` 게이팅 룰(`…011`~`…018`)을 한 곳에서 정리한다.
> 각 룰 파일의 게이트별 `<id>.md` 문서는 이 문서로 대체한다(중복 제거).
> 게이트 룰은 **공격 탐지 룰이 아니라 흐름 제어 룰**이다.

---

## 0. 한 줄 요약

> 게이트 룰 = "현재 **paranoia level(PL)** 에 따라 아래 PL 구간 룰을 **실행하거나 건너뛰는**" 제어 룰.

---

## 1. paranoia level(PL)이란

- CRS는 룰을 **PL1 / PL2 / PL3 / PL4** 구간으로 나눈다. 높을수록 민감하고 오탐 위험이 크다.
- 값은 관리자가 정한다(자동 증가 아님). 기본값은 **1**.
- 두 종류가 있다.

| 변수 | 뜻 | 기본 |
|------|-----|------|
| `tx.blocking_paranoia_level` | 이 PL까지의 점수를 **차단 계산에 반영** | 1 |
| `tx.detection_paranoia_level` | 이 PL까지의 룰을 **실행** | =blocking |

- 설정: `crs-setup.conf` `900000`/`900001` (기본은 **주석 처리 = 미설정**).
- 미설정이면 `REQUEST-901-INITIALIZATION.conf`의 `901120`/`901125`가 **1**로 채운다.

---

## 2. 게이트 룰의 형태

```
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt N" \
    "id:XXXXXX, phase:1|2, pass, nolog, tag:'OWASP_CRS', \
     skipAfter:END-<파일-이름>"
```

- **검사**: `TX:DETECTION_PARANOIA_LEVEL @lt N` → "탐지 PL이 N 미만인가?"
- **매칭되면**: `pass`(차단하지 않음) + `skipAfter:END-…`(그 phase의 `SecMarker`까지 건너뜀).
- **phase 1 / phase 2 쌍**으로 존재한다. `skipAfter`는 그 룰이 실행되는 **phase 안에서만**
  뒤 룰을 건너뛸 수 있어, phase 1 룰 목록과 phase 2 룰 목록을 각각 커버하려면 쌍이 필요하다.

---

## 3. `@lt N` → 건너뛰는 범위

| 게이트 (`@lt N`) | 매칭 조건 | 건너뛰는 구간 | PL=1 | PL=2 | PL=3 | PL=4 |
|------------------|-----------|---------------|------|------|------|------|
| `…011`/`…012` | PL < 1 | PL1~4 전체 | 미매칭 | 미매칭 | 미매칭 | 미매칭 |
| `…013`/`…014` | PL < 2 | PL2~4 | **매칭** | 미매칭 | 미매칭 | 미매칭 |
| `…015`/`…016` | PL < 3 | PL3~4 | (도달 전 skip) | **매칭** | 미매칭 | 미매칭 |
| `…017`/`…018` | PL < 4 | PL4 | (도달 전 skip) | (도달 전 skip) | **매칭** | 미매칭 |

- 조건이 **참이면 그 구간부터 끝(END)까지 건너뛴다.**
- 조건이 **거짓이면 아무 동작 없이** 다음 룰(그 구간)이 실행된다.

---

## 4. 파일 구조 예시

```
[PL1 게이트]  SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" ... skipAfter:END
── Paranoia Level 1 구간 ──   (예: 911100)
[PL2 게이트]  SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" ... skipAfter:END
── Paranoia Level 2 구간 ──
[PL3 게이트]  SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 3" ... skipAfter:END
── Paranoia Level 3 구간 ──
[PL4 게이트]  SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 4" ... skipAfter:END
── Paranoia Level 4 구간 ──
SecMarker "END-<파일-이름>"
```

- 각 PL 구간의 룰은 **자기 게이트 바로 뒤 ~ 다음 게이트 앞**에 놓인다.
- 상위 PL 구간은 비어 있을 수 있다(예: REQUEST-911은 PL2~4가 비어 있음).

---

## 5. 기본값(PL=1)에서의 동작

1. `…011`/`…012` (`@lt 1`): `1 < 1` 거짓 → **미매칭** → 통과
2. `…013`/`…014` (`@lt 2`): `1 < 2` 참 → **매칭** → PL2~4 구간 `END`로 점프
3. `…015`~`…018`: 이미 점프되어 도달하지 않음

→ 결과적으로 **PL1 구간 룰만 실행**된다. (예: `911100`)

### 예: detection PL = 2
- `@lt 1`, `@lt 2`: 거짓 → PL1~2 구간 실행
- `@lt 3`: 참(`2 < 3`) → PL3~4 구간 skip

---

## 6. 자주 하는 오해

- **"`@lt 1` 게이트는 왜 있나?"** → CRS가 파일을 **규칙적으로 자동 생성**하기 때문(PL0 경계).
  PL은 1 미만이 될 수 없어 **실제로는 절대 매칭되지 않는다(dead gate).**
- **"`pass` = 건너뛰지 않는다?"** → 아니다. `pass`는 **"차단하지 않는다"** 는 뜻이고,
  게이트는 `pass`이면서 동시에 `skipAfter`로 **건너뛴다.**
- **detection PL을 올리면?** → 상위 구간 룰까지 **실행**된다(점수는 각 구간 버킷 `pl1`~`pl4`에 적립).
  실제 **차단 반영 범위는 `blocking_paranoia_level`.**
- **점수와의 관계** → 점수/차단 연결은 [score-and-paranoia.md](score-and-paranoia.md) 참고.

---

## 7. 예외: PL 게이트가 아닌 `skipAfter` 제어 룰

`skipAfter`를 쓰지만 **PL 게이트가 아닌** 제어 룰들이다(자동 생성기에서 게이트로 오분류되던 것들).
이 룰들도 공격 탐지가 아니라 흐름 제어이며, 공통 문서인 이 문서로 대체한다.

| id | 파일 | 조건 | 동작 |
|----|------|------|------|
| `950021` | RESPONSE-950 | `TX:crs_skip_response_analysis == 1` | `END-RESPONSE-959-...`까지 skip (응답 분석 전체 생략) |
| `950010` | RESPONSE-950 | `RESPONSE_HEADERS:Content-Encoding` ∈ {gzip,compress,deflate,br,zstd} | `END-RESPONSE-950-...`까지 skip (압축 본문) |
| `951010` | RESPONSE-951 | 위와 동일(압축 본문) | `END-RESPONSE-951-...`까지 skip |
| `951100` | RESPONSE-951 | `RESPONSE_BODY !@pmFromFile sql-errors.data` (SQL 에러 미탐지) | `END-SQL-ERROR-MATCH-PL1`까지 skip |
| `952010` | RESPONSE-952 | 압축 본문 | `END-RESPONSE-952-...`까지 skip |
| `953010` | RESPONSE-953 | 압축 본문 | `END-RESPONSE-953-...`까지 skip |
| `954010` | RESPONSE-954 | 압축 본문 | `END-RESPONSE-954-...`까지 skip |
| `955010` | RESPONSE-955 | 압축 본문 | `END-RESPONSE-955-...`까지 skip |
| `956010` | RESPONSE-956 | 압축 본문 | `END-RESPONSE-956-...`까지 skip |
| `980041`~`980050` | RESPONSE-980 | `TX:REPORTING_LEVEL` / 점수 조건 (phase 5) | `END-REPORTING` 또는 `LOG-REPORTING`까지 skip (보고 상세도 제어) |

> `98xxx` 게이트는 `tx.reporting_level`(0~5)에 따라 phase 5 상세 로깅 범위를 제어한다.
> 자세한 값 의미는 [base-rules/crs-setup-conf.md](base-rules/crs-setup-conf.md) 참고.

---

## 8. 참고

- 실행 모델(phase/skipAfter): [execution-model.md](execution-model.md)
- 점수/차단과의 연결: [score-and-paranoia.md](score-and-paranoia.md)
- PL 정책 변수(`900000`/`900001`): [base-rules/crs-setup-conf.md](base-rules/crs-setup-conf.md)
