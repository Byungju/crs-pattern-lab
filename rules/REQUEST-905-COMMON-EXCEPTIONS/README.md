# REQUEST-905-COMMON-EXCEPTIONS.conf 분석 및 검증

분석 대상: `install/nginx/conf/crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf`
(원본: `coreruleset/rules/REQUEST-905-COMMON-EXCEPTIONS.conf`, CRS **4.30.0-dev**)

## 1. 개요

이 파일은 **예외(exception/화이트리스트) 전용** 파일로, 공격을 탐지/차단하지 않는다.
로컬 헬스체크 트래픽에 대해 **CRS 룰을 제거**하여 불필요한 오탐/로그를 없애는 것이 목적이다.

- 룰 2개: `905100`(Apache SSL pinger), `905110`(Apache internal dummy connection)
- 둘 다 `phase:1`, `nolog`, `pass` + chain 이며, 마지막에 다음을 수행한다.
  - `ctl:ruleRemoveByTag=OWASP_CRS` — 해당 트랜잭션에서 CRS 룰 전체 비활성
  - `ctl:auditEngine=Off` — 해당 트랜잭션 audit 로그 비활성
- 즉 **"무엇을 막는" 룰이 아니라 "무엇을 면제하는" 룰**이다.

## 2. 룰 목록

| ID | 조건(모두 충족) | 동작 | 실측 |
|----|----------------|------|------|
| [905100](905100.md) | `REQUEST_LINE @streq GET /` + `REMOTE_ADDR @ipMatch 127.0.0.1,::1` | CRS 제거 + audit off | **미발동**(조건 불일치) |
| [905110](905110.md) | `REMOTE_ADDR` localhost + `User-Agent @endsWith (internal dummy connection)` + `REQUEST_LINE @rx ^(GET /\|OPTIONS \*) HTTP/[12]\.[01]$` | CRS 제거 + audit off | **정상(PASS)** |

## 3. 핵심 발견

- **905100 은 이 환경(nginx + libmodsecurity v3)에서 발동하지 않는다.**
  `REQUEST_LINE` 은 `GET / HTTP/1.1`(프로토콜 포함)인데 조건은 `@streq GET /` 라 불일치한다.
- **905110 은 정상 발동한다.** 조건이 HTTP 버전까지 포함해 매칭하기 때문이다.
- 두 룰 모두 `nolog` 이므로 직접 로그를 남기지 않는다 → 효과를 **다른 룰(920350)의 유무**로 간접 검증.

## 4. 검증 (테스트 하네스)

`tests/` 디렉토리에 룰 id 기반 검증이 있다.

```
tests/
├── lib.sh        # 공용 라이브러리 (테스트 nginx 기동, 920350/audit 카운트)
├── verify.sh     # 룰 id 케이스 레지스트리
├── run-all.sh    # 전체 실행 -> logs/run-all.log
├── 905100.sh / 905110.sh
└── logs/<rule-id>.log
```

### 검증 방식

`Host: 127.0.0.1`(numeric) 요청 시 정상적으로 발생하는 CRS 룰 **920350** 을 "탐지 표식"으로 쓴다.

- 예외 적용 → `OWASP_CRS` 룰 제거 → **920350 사라짐(=0)** + audit **미기록(=0)**
- 예외 미적용 → **920350 기록(=1)** + audit 기록

`REMOTE_ADDR` 는 테스트가 127.0.0.1 에서 접속하므로 예외의 로컬 조건을 만족한다.

### 실행

```bash
cd rules/REQUEST-905-COMMON-EXCEPTIONS/tests
./run-all.sh          # 전체
./905110.sh           # 개별
```

### 현재 결과

```
PASS=4  FAIL=0  SKIP=1
```

- `905100` 은 SKIP(실환경 미발동, 조건 불일치) — 근거는 로그 참고.

### 로그 위치

스크립트가 생성하는 로그는 프로젝트 루트의 **임시 테스트 전용 디렉토리**
`logs/local_test/REQUEST-905-COMMON-EXCEPTIONS/` 에 모은다(보존).

| 파일 | 내용 |
|------|------|
| `logs/local_test/REQUEST-905-COMMON-EXCEPTIONS/run-all.log` | 전체 실행 |
| `logs/local_test/REQUEST-905-COMMON-EXCEPTIONS/<rule-id>.log` | 룰별 결과 + 근거 |
| `logs/local_test/REQUEST-905-COMMON-EXCEPTIONS/nginx-error.log` | 테스트 nginx error log |
| `logs/local_test/REQUEST-905-COMMON-EXCEPTIONS/nginx-audit.log` | 테스트 audit log |

테스트에서는 `modsecurity.conf` 의 `SecAuditEngine RelevantOnly` 를 `On` 으로 덮어써
모든 트랜잭션이 audit 로그에 남도록 한다(예외 미적용 케이스 확인용).

## 5. 참고

- `ctl:ruleRemoveByTag` / `ctl:auditEngine` 은 ModSecurity `ctl` 액션이다.
- 실행 모델(설정 vs 룰, phase): [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 관련: [REQUEST-901-INITIALIZATION](../REQUEST-901-INITIALIZATION/README.md)
