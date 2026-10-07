# REQUEST-911-METHOD-ENFORCEMENT.conf — 쉽게 읽는 분석

> 이 문서는 **HTTP 메서드 정책**을 강제하는 CRS 파일을, ModSecurity를 처음 보는 사람도
> 이해할 수 있도록 "기초 → 룰 관계 → 요청 흐름" 순서로 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

이 문서를 읽으려면 딱 4가지만 알면 된다.

### (1) 룰(Rule)은 "무엇을(변수) / 어떻게(연산자)" 검사하고 "무엇을 할지(action)" 정한다

```
SecRule  REQUEST_METHOD   "!@within %{tx.allowed_methods}"   "phase:1, block, setvar:... "
        └─ 검사 대상(변수)   └─ 검사 방법(연산자)                 └─ 매칭 시 할 일(액션)
```

- **변수**: 요청에서 꺼낸 값. 예: `REQUEST_METHOD`(메서드), `REQUEST_URI`(경로), `ARGS`(파라미터).
- **연산자**: 비교 방법. `@within`(목록에 포함), `@rx`(정규식), `@streq`(문자열 일치) 등.
- **액션**: 매칭됐을 때 할 일. `log`(로그), `deny`(차단), `pass`(통과), `setvar`(값 설정) 등.

### (2) 처리는 "phase(단계)" 순서로 진행된다

| phase | 시점 |
|-------|------|
| **1** | 요청 **헤더**를 받은 직후 (메서드/경로/헤더 검사) |
| **2** | 요청 **본문**까지 받은 뒤 (파라미터/본문 검사) |
| 3 / 4 | 응답 헤더 / 응답 본문 |
| 5 | 로깅 |

→ 이 파일의 룰은 대부분 **phase 1**, 차단 판정은 **phase 2** 에서 일어난다.

### (3) CRS는 "어노말리 스코어(anomaly score)" 방식으로 차단한다

- 룰이 매칭되면 **즉시 막지 않고 점수만 쌓는다.**
- phase 2 끝에서 점수가 임계값(기본 5)을 넘으면 **`949110` 룰이 403으로 차단**한다.
- 그래서 "탐지한 룰(911100)"과 "실제로 막는 룰(949110)"이 서로 다른 파일에 있다.

### (4) `tx.변수` 는 요청마다 새로 만들어지는 임시 값

- `tx.allowed_methods` 처럼 `tx.` 로 시작하는 값은 **그 요청에서만** 유효하다.
- 매 요청 시작 시 `901-INITIALIZATION` 파일이 기본값을 채운다.

> 더 자세한 실행 모델은 [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md) 참고.

---

## 1. 한 줄 요약

> **"허용 목록(`tx.allowed_methods`)에 없는 HTTP 메서드로 요청하면, CRS가 403으로 막는다."**

기본 허용 목록은 `GET HEAD POST OPTIONS` 이므로, `PUT` / `DELETE` / `PATCH` 같은 메서드는 차단된다.

---

## 2. 룰

이 파일에는 성격이 다른 **두 종류**의 룰이 있다. 이 관계를 이해하는 게 핵심이다.

```
[설정값]                         [탐지]                    [실제 차단]
901160 / crs-setup 900200  ──▶  tx.allowed_methods
                                        │ (참조)
                                        ▼
                                  911100  ── 점수 +5 ──▶  949110  ──▶  HTTP 403
                                                                 (다른 파일: REQUEST-949)
                                        ▲
                911011 ~ 911018 ────────┘
                (PL 게이팅: 911100 등 각 PL 구간 룰을 실행할지/건너뛸지 결정)
                                        │
                               SecMarker "END-REQUEST-911-METHOD-ENFORCEMENT"
                               (건너뛸 때 도착하는 목적지 표시)
```

| 룰 | 종류 | 한 줄 역할 |
|----|------|-----------|
| [911100](911100.md) | **탐지** | 메서드가 허용 목록 밖이면 **점수 5를 쌓는다** (이 룰 자체는 즉시 막지 않음) |
| [911011](../../modsecurity/paranoia-gating.md)~[911018](../../modsecurity/paranoia-gating.md) | **게이팅(제어)** | paranoia level 에 따라 아래 PL 구간 룰을 **실행/건너뛰기**만 결정 (공격 탐지 아님) |
| `SecMarker END-...` | 표식 | 게이팅 룰이 "여기로 점프"할 목적지 |
| `949110` (다른 파일) | **차단** | 쌓인 점수가 임계값을 넘으면 **403** 을 반환 |

### 왜 게이팅 룰(911011~911018)이 필요한가? — paranoia level 개념

> 게이트 개념 정본: [../../modsecurity/paranoia-gating.md](../../modsecurity/paranoia-gating.md)
> (게이트별 `<id>.md` 문서는 이 공통 문서로 통합됨)

- CRS는 룰을 **paranoia level(PL, 1~4)** 로 나눈다. PL이 높을수록 더 많은/민감한 룰이 켜진다.
- 파일은 `PL1 구간`, `PL2 구간`, … 식으로 나뉘어 있고, 각 구간 앞에
  "현재 PL이 이 구간보다 낮으면 **끝(END)으로 점프**" 하는 룰이 놓인다.
- 예: `911013` = `detection_pl < 2` 이면 PL2 구간을 건너뛴다.
- 기본값은 `detection_pl = 1` 이므로 **PL1 구간(911100)만 실행**되고, PL2~4 구간은 건너뛴다.
  (참고: 이 파일의 PL2~4 구간은 실제로 비어 있다. 그래서 게이팅 룰은 "탐지"가 아니라 "제어"다.)

---

## 3. `PUT /` 요청이 403이 되기까지 (단계별)

```
1) 요청 도착: PUT /
2) phase 1 · 901-INITIALIZATION
      → tx.allowed_methods = "GET HEAD POST OPTIONS" 로 기본값 설정
3) phase 1 · 911100
      → PUT 은 목록에 없음(!@within) → 매칭
      → tx.inbound_anomaly_score_pl1 에 +5 누적   (아직 차단 아님)
4) phase 1 · 911013 (게이팅)
      → detection_pl(1) < 2 이므로 END 로 점프 → PL2~4 구간 skip
5) phase 2 끝 · 949110 (다른 파일)
      → 누적 점수 5 >= 임계값 5 → deny → HTTP 403
6) 응답: 403, 로그에 911100 + 949110 기록
```

`GET /` 처럼 허용된 메서드면 3)에서 매칭되지 않아 점수 0 → 200 으로 통과한다.

---

## 4. 공격 예제 및 실측 결과

"정책에 없는 메서드로 요청"이 이 룰의 공격 예제다.

| 메서드 | HTTP | 911100 | 949110 | 해설 |
|--------|------|--------|--------|------|
| `PUT /` | **403** | 매칭 | 매칭 | 차단 |
| `DELETE /` | **403** | 매칭 | 매칭 | 차단 |
| `PATCH /` | **403** | 매칭 | 매칭 | 차단 |
| `GET /` | 200 | 없음 | 없음 | 허용(대조군) |
| `HEAD /` | 200 | 없음 | 없음 | 허용(대조군) |
| `OPTIONS /` | 405 | 없음 | 없음 | nginx가 먼저 거부 |
| `POST /` | 405 | 없음 | 없음 | 정적 리소스라 nginx가 먼저 거부 |
| `TRACE /` | 405 | 없음 | 없음 | nginx가 CRS 도달 전에 거부 |
| `CONNECT /` | 400 | 없음 | 없음 | nginx가 잘못된 요청으로 거부 |

> 주의: `TRACE`/`OPTIONS`/`POST` 등은 **nginx가 ModSecurity보다 먼저 405/400** 을 반환할 수 있다.
> 그래서 검증은 확실히 CRS까지 도달하는 `PUT`/`DELETE`/`PATCH` 로 한다.

---

## 5. 검증 실행

```
tests/
├── lib.sh        # 테스트용 nginx 기동, 메서드 요청, 룰 로그 카운트
├── verify.sh     # 룰 id별 검증 케이스
├── run-all.sh    # 전체 실행
├── 911100.sh / 911011.sh ... (룰 id별)
└── (로그: ../../../logs/local_test/REQUEST-911-METHOD-ENFORCEMENT/)
```

```bash
cd rules/REQUEST-911-METHOD-ENFORCEMENT/tests
./run-all.sh      # 전체
./911100.sh       # 탐지 룰만
```

현재 결과:
```
PASS=13  FAIL=0  SKIP=8
```
- `911100` — 공격 예제(PUT/DELETE/PATCH) 403 + 로그 확인, 허용(GET/HEAD) 통과.
- `911011`~`911018` — 탐지 룰이 아니라 PL 제어 룰이라 SKIP.

로그: `logs/local_test/REQUEST-911-METHOD-ENFORCEMENT/` (`run-all.log`, `<rule-id>.log`,
`nginx-error.log`, `nginx-audit.log`)

---

## 6. 용어 미니 사전

| 용어 | 뜻 |
|------|-----|
| `SecRule` | ModSecurity 룰 한 줄 (변수 + 연산자 + 액션) |
| 변수(variable) | 검사 대상 값 (예: `REQUEST_METHOD`) |
| 연산자(operator) | 비교 방법 (예: `@within`, `@rx`) |
| phase | 처리 단계 (1=요청헤더, 2=요청본문, 3/4=응답, 5=로깅) |
| action | 매칭 시 동작 (`log`, `deny`, `block`, `setvar`, `pass`) |
| `tx.*` | 요청마다 초기화되는 임시 변수 |
| 어노말리 스코어 | 룰이 쌓는 위험 점수, 임계값 넘으면 `949110`이 차단 |
| paranoia level(PL) | 룰 민감도 단계(1~4), 높을수록 룰 많음 |
| `skipAfter` | 지정한 마커까지 건너뛰기 |
| `SecMarker` | `skipAfter` 목적지로 쓰이는 표식 |

---

## 7. 참고

- 실행 모델(설정 vs 룰, phase): [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- `allowed_methods` 초기화: [REQUEST-901 901160](../REQUEST-901-INITIALIZATION/901160.md)
- 관련: [REQUEST-905-COMMON-EXCEPTIONS](../REQUEST-905-COMMON-EXCEPTIONS/README.md)
- 정책 변경: `crs-setup.conf` 의 `900200`(`tx.allowed_methods`)
