# ModSecurity 실행 모델 (설정 vs 룰, phase)

ModSecurity(nginx 커넥터)가 **언제 무엇을 하는지** 정리한다. 룰 파일을 분석할 때
"이 룰이 요청/응답 어느 시점에, 매 요청마다 도는지" 를 이해하기 위한 전제 문서다.

## 0. 핵심: 두 가지를 구분하자

| 구분 | 예 | 시점 |
|------|-----|------|
| **Configuration (Directive)** | `SecRuleEngine`, `SecRequestBodyAccess`, `SecTmpDir`, `SecPcreMatchLimit`, `SecAuditLog*`, `SecDebugLog*` | nginx **기동/리로드 시 1회** 적용 |
| **Rule (`SecRule`/`SecAction`)** | `SecRule ... id:942100`, `SecAction ... id:901200` | **매 HTTP 트랜잭션**마다, 지정한 **phase**에서 실행 |
| **룰 기본동작 Directive** | `SecDefaultAction` | 기동 시 1회 정의 → 룰에 상속 |
| **정책 변수 SecAction** | `tx.blocking_paranoia_level=1` | phase 1에서 **매 요청 실행** (트랜잭션 변수 초기화) |

즉 "접속할 때 설정을 진행"하는 것이 아니라, **설정은 시작할 때 한 번**, **룰은 요청이 들어와
응답이 나갈 때까지 phase 별로** 실행된다.

## 1. nginx 커넥터가 룰을 호출하는 지점

ModSecurity-nginx 는 nginx 의 특정 단계에 훅을 등록하고, 그 시점에 libmodsecurity 의
`msc_process_*` 를 호출한다. (소스: `src/ModSecurity-nginx/src/`)

| nginx 단계 | 커넥터 호출 (파일:라인) | ModSecurity phase |
|-----------|------------------------|-------------------|
| ACCESS_PHASE | `msc_process_connection` (`ngx_http_modsecurity_access.c:163`) | phase 1 |
| ACCESS_PHASE | `msc_process_uri` (`...access.c:225`) | phase 1 |
| ACCESS_PHASE | `msc_process_request_headers` (`...access.c:275`) | **phase 1** (요청 헤더/URI) |
| ACCESS_PHASE (본문 도착 후) | `msc_process_request_body` (`...access.c:444`) | **phase 2** (요청 본문) |
| 응답 header filter | `msc_process_response_headers` (`...header_filter.c:529`) | **phase 3** (응답 헤더) |
| 응답 body filter | `msc_process_response_body` (`...body_filter.c:163`) | **phase 4** (응답 본문) |
| LOG_PHASE | `msc_process_logging` (`...log.c:71`) | **phase 5** (로깅) |

설정/룰 로드는 main conf 초기화 시점에 일어난다:
`msc_init()` (`ngx_http_modsecurity_module.c:662`), `msc_create_rules_set()` (`:723`).

## 2. 트랜잭션 타임라인

```
[nginx 기동 / reload]
  modsecurity.conf, crs-setup.conf, rules/*.conf 파싱
  → directive 적용 (SecRuleEngine, SecRequestBodyAccess, SecAuditLog ...)
  → 룰 컴파일

[클라이언트 요청 도착]
  phase 1  요청 헤더/URI
           - 901-INITIALIZATION 대부분 (TX 변수 초기화)
           - REQUEST-911(METHOD), 913(SCANNER), 920(헤더 관련) ...
  phase 2  요청 본문
           - REQUEST-920(본문), 921, 930~944 (LFI/RFI/RCE/SQLi/XSS ...)
           - 끝에서 949-BLOCKING-EVALUATION → 여기서 차단(403) 결정
             └ 차단이면 응답, 아니면 업스트림/정적 처리
  phase 3  응답 헤더
  phase 4  응답 본문  (SecResponseBodyAccess On + MIME 일치 시)
           - RESPONSE-950~956 (데이터 유출)
  phase 5  로깅
           - audit log 기록, RESPONSE-980 (상관분석)
```

## 3. 룰이 "매 요청" 실행되는데 트랜잭션 변수는 어떻게 초기화되나

- `tx.*` 는 **트랜잭션(요청) 마다 새로** 만들어진다.
- 그래서 901-INITIALIZATION 이 phase 1에서 매번 기본값을 넣고(`&TX:... @eq 0` idiom),
  901200 은 점수를 0 으로 초기화한다.
- 반면 `SecRuleEngine` 같은 directive 는 모든 요청에 공통 적용되는 엔진 설정이다.

## 4. 예시로 보는 실행

### 4.1 정상 요청 (GET /)
```
phase 1: 901001(&TX:crs_setup_version==0? no) → 통과, 901xxx 변수 초기화
phase 2: 949 점수 0 → 차단 없음
phase 3/4: 응답 (필요 시)
phase 5: SecAuditEngine RelevantOnly 이고 200 이면 audit log 없음
```

### 4.2 SQLi 요청 (/?id=1' OR '1'='1)
```
phase 1: 초기화
phase 2: 942100 매칭 → tx.critical_anomaly_score(5) 누적
         → 949110: TX:BLOCKING_INBOUND_ANOMALY_SCORE >= 5 → deny 403
phase 5: auditlog action 으로 표시된 트랜잭션 → audit log 기록
```

### 4.3 crs-setup 누락 (설정 오류)
```
phase 1: 901001 매칭(&TX:crs_setup_version==0) → deny 500  (업스트림 미도달)
```

`901001` 이 phase 1 이므로, 공격 여부와 무관하게 **요청 처리 초입에** 설정 문제를 잡는다.

## 5. 로그가 "남는" 조건

로그 종류와 남는 조건이 각각 다르다.

| 로그 | directive | 남는 조건 |
|------|-----------|-----------|
| error log | `log` action | 룰에 `log` 가 있고(=`nolog` 없음) 매칭될 때 |
| audit log | `SecAuditEngine` | `On`=모든 트랜잭션, `RelevantOnly`(권장)=**로깅되는 룰(`log`/`auditlog`)이 매칭된 트랜잭션** |
| debug log | `SecDebugLogLevel` | 0=꺼짐, 1~9 로 올리면 상세 로그 |

측정 결과(이 환경):
- `RelevantOnly` + 룰 매칭(`log` 또는 `auditlog`) → **상태코드와 무관하게 audit 기록** (404 포함)
- `RelevantOnly` + 룰에 `nolog` → audit 미기록
- `RelevantOnly` + 매칭 룰 없음(정적 200 등) → audit 미기록
- `On` → 룰 매칭 여부와 무관하게 **모든 트랜잭션** audit 기록

- CRS 초기화 룰(901xxx)은 대부분 **`nolog`** 이라 error/audit 로그가 남지 않는다(의도된 동작).
  → "테스트했는데 로그가 없다"의 가장 큰 이유.
- `log`/`auditlog` 를 가진 룰이 매칭되면 audit 로그에 남는다.

> 이 프로젝트의 테스트 하네스는 `On` + 전용 audit 로그를 써서 **매칭되지 않는 요청(정적 200, 404 probe 등)까지
> 모두** audit 로그에 남기고, 로그 파일을 삭제하지 않고 보존한다.
> 자세한 내용은 [`../rules/REQUEST-901-INITIALIZATION/README.md`](../rules/REQUEST-901-INITIALIZATION/README.md) 참고.

## 6. 참고

- ModSecurity Reference Manual (v3.x): <https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)>
- nginx 커넥터 소스: `src/ModSecurity-nginx/src/`
- 엔진 directive 분석: [base-rules/modsecurity-conf.md](base-rules/modsecurity-conf.md)
