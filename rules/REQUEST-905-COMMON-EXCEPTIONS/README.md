# REQUEST-905-COMMON-EXCEPTIONS.conf — 쉽게 읽는 분석

> 이 문서는 CRS의 **예외(화이트리스트) 파일**을 "기초 → 역할 → 룰 → 흐름 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

### (1) 룰은 "무엇을(변수) / 어떻게(연산자)" 검사하고 "무엇을 할지(action)" 정한다

- **변수**: `REQUEST_LINE`(요청 첫 줄), `REMOTE_ADDR`(접속 IP), `REQUEST_HEADERS:User-Agent` 등.
- **연산자**: `@streq`(문자열 완전 일치), `@ipMatch`(IP 범위), `@endsWith`(끝 문자열), `@rx`(정규식).
- **액션**: `pass`(통과), `nolog`(로그 안 남김), `ctl:...`(동작 제어) 등.

### (2) `chain` = 여러 조건을 AND로 연결

`chain` 액션을 쓰면 **다음 룰과 한 세트**로 묶여, **모든 조건이 참일 때만** 마지막 액션이 실행된다.
이 파일의 룰은 모두 `chain` 으로 2~3개 조건을 묶고 있다.

### (3) `ctl:` 액션 = 그 요청에 한해 엔진 동작을 바꾼다

이 파일이 쓰는 두 가지:

| ctl | 뜻 |
|-----|-----|
| `ctl:ruleRemoveByTag=OWASP_CRS` | **그 요청에서 CRS 룰 전체를 끈다** |
| `ctl:auditEngine=Off` | **그 요청은 audit 로그에 남기지 않는다** |

> 이 파일은 **탐지/차단 파일이 아니라 "면제" 파일**이다.
> 즉 "무엇을 막는 룰"이 아니라 "무엇을 봐주는 룰"이다.

---

## 1. 한 줄 요약

> **로컬(127.0.0.1)에서 오는 서버 자체 헬스체크 요청을, CRS가 오탐하지 않도록 잠시 면제해 주는 파일.**

---

## 2. 룰

| ID | 조건(모두 충족) | 동작 | 실측 |
|----|----------------|------|------|
| [905100](905100.md) | `REQUEST_LINE @streq GET /` + `REMOTE_ADDR @ipMatch 127.0.0.1,::1` | CRS 제거 + audit off | **미발동**(조건 불일치) |
| [905110](905110.md) | `REMOTE_ADDR` localhost + `User-Agent @endsWith (internal dummy connection)` + `REQUEST_LINE @rx ^(GET /\|OPTIONS \*) HTTP/[12]\.[01]$` | CRS 제거 + audit off | **정상(PASS)** |

- `905100` 대상: Apache **SSL pinger**(로컬 헬스체크)
- `905110` 대상: Apache **internal dummy connection**(내부 연결 확인)
- 둘 다 `phase:1`, `nolog`, `pass` + `chain`.

---

## 3. 핵심 발견 (왜 905100은 안 되나)

- **905100 은 이 환경(nginx + libmodsecurity v3)에서 발동하지 않는다.**
  - 조건은 `REQUEST_LINE` 이 **정확히 `GET /`** 일 때인데,
  - 실제 값은 **`GET / HTTP/1.1`** (HTTP 버전 포함)이라 불일치한다.
  - → 자세한 배경은 [905100.md](905100.md)의 "배경" 섹션 참고.
- **905110 은 정상 발동한다.** 조건에 HTTP 버전까지 포함(`HTTP/[12].[01]`)해서 실제 값과 맞기 때문이다.
- 두 룰 모두 `nolog` 이라 **직접 로그를 남기지 않는다.**
  → 그래서 효과를 **다른 룰(920350)의 유무**로 간접 확인한다.

---

## 4. 흐름 / 관계

```
로컬 요청 (127.0.0.1)
  phase 1 · 905100/905110 조건 검사
        ├─ 조건 충족 → ctl:ruleRemoveByTag=OWASP_CRS + ctl:auditEngine=Off
        │             → 그 요청은 CRS가 검사/기록하지 않음
        └─ 조건 불충족 → 그냥 통과 → 이후 CRS 룰이 정상 동작
```

관계:
- 이 파일은 **CRS를 "끄는" 룰**이므로, 뒤따르는 CRS 룰들(예: `920350`)보다 **먼저(phase 1)** 실행된다.
- `920350`(Host가 숫자 IP) 같은 정상 룰이 로컬 헬스체크에서 오탐하지 않게 막아주는 용도다.

---

## 5. 검증 (테스트 하네스)

```
tests/
├── lib.sh        # 테스트 nginx 기동, 920350/audit 카운트
├── verify.sh     # 룰 id별 검증 케이스
├── run-all.sh    # 전체 실행
├── 905100.sh / 905110.sh
└── (로그: ../../../logs/local_test/REQUEST-905-COMMON-EXCEPTIONS/)
```

### 검증 방식 — 920350을 "탐지 표식"으로 사용

`Host: 127.0.0.1`(숫자 IP) 요청은 정상 시 CRS 룰 **920350** 을 발생시킨다.
예외가 적용되면 CRS가 꺼져서 920350이 사라지므로, 이걸로 확인한다.

- 예외 적용 → `920350 = 0` + audit `= 0`
- 예외 미적용 → `920350 = 1` + audit 기록

### 실행

```bash
cd rules/REQUEST-905-COMMON-EXCEPTIONS/tests
./run-all.sh          # 전체
./905110.sh           # 개별
```

현재 결과: `PASS=4  FAIL=0  SKIP=1`
- `905100` 은 SKIP(실환경 미발동) — 근거는 로그 참고.
- `905110` 은 트리거 2건 + 대조군 2건 PASS.

### 로그 위치

`logs/local_test/REQUEST-905-COMMON-EXCEPTIONS/` 에 모아 보존한다.

| 파일 | 내용 |
|------|------|
| `run-all.log`, `<rule-id>.log` | 전체 / 룰별 결과 + 근거 |
| `nginx-error.log` | 테스트 nginx error log |
| `nginx-audit.log` | 테스트 audit log |

> 테스트에서는 `SecAuditEngine On` 으로 덮어써 **모든 트랜잭션**이 audit 로그에 남게 한다
> (예외 미적용 케이스 확인용).

---

## 6. 용어 미니 사전

| 용어 | 뜻 |
|------|-----|
| `chain` | 여러 조건을 AND로 연결 |
| `ctl:` | 그 요청에 한해 엔진 동작 제어 |
| `ruleRemoveByTag` | 태그에 해당하는 룰들을 제거 |
| `auditEngine=Off` | audit 로그 비활성 |
| `@streq` / `@ipMatch` / `@endsWith` / `@rx` | 문자열 일치 / IP 범위 / 접미사 / 정규식 |
| `nolog` | error/audit 로그를 남기지 않음 |

---

## 7. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 관련: [REQUEST-901-INITIALIZATION](../REQUEST-901-INITIALIZATION/README.md),
  [REQUEST-911-METHOD-ENFORCEMENT](../REQUEST-911-METHOD-ENFORCEMENT/README.md)
