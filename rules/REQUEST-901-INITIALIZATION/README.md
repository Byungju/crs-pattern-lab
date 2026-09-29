# REQUEST-901-INITIALIZATION.conf 분석 및 검증

분석 대상: `install/nginx/conf/crs/rules/REQUEST-901-INITIALIZATION.conf`
(원본: `coreruleset/rules/REQUEST-901-INITIALIZATION.conf`, CRS **4.30.0-dev**)

## 1. 개요

이 파일은 CRS 의 **초기화/준비 파일**이다. 공격을 탐지하는 룰이 아니라,

- CRS 설정(`crs-setup.conf`)이 올바른 순서로 로드되었는지 확인하고,
- 설정이 누락된 변수에 **안전한 기본값**을 채우고,
- 어노말리 스코어 변수와 컬렉션을 **0/빈 값으로 초기화**하며,
- body processor / 샘플링 결정을 준비한다.

특징:

- `SecComponentSignature "OWASP_CRS/4.30.0-dev"` 로 CRS 버전을 audit log Producer 라인에 남긴다.
- 파일의 대부분(31개 룰 + SecMarker)은 `phase:1` 에서 동작한다.
- 대다수 룰이 **`nolog`** 이라 감사/에러 로그를 남기지 않는다.
  → 검증 시 로그 대신 **TX 변수 값(probe)** 또는 **디버그 로그**를 사용한다.
- 파일 로드 순서: `modsecurity.conf` → `crs-setup.conf` → **이 파일** → 나머지 `rules/*.conf`.

> 이 파일은 공격 탐지 룰이 아니므로 "공격 payload" 대신 **설정/상태 검증** 방식으로
> 검증한다. (공격 payload 기반 검증은 `REQUEST-9xx` 탐지 룰에서 진행)

## 2. 룰 목록

각 룰의 **상세 설명은 같은 디렉토리의 `<rule-id>.md`** 파일에 있다 (아래 표의 ID 링크).
검증 스크립트는 `tests/<rule-id>.sh`, 실행 로그는 `tests/logs/<rule-id>.log` 로 이름이 일치한다.

### 2.1 설정 로드 확인 / 기본값 채움

| ID | phase | action | 대상 변수 | 기본값 | 로그 |
|----|-------|--------|-----------|--------|------|
| [901001](901001.md) | 1 | deny(500) | `TX:crs_setup_version` | (없으면 차단) | log+auditlog |
| [901100](901100.md) | 1 | pass,nolog | `tx.inbound_anomaly_score_threshold` | 5 | - |
| [901110](901110.md) | 1 | pass,nolog | `tx.outbound_anomaly_score_threshold` | 4 | - |
| [901111](901111.md) | 1 | pass,nolog | `tx.reporting_level` | 4 | - |
| [901115](901115.md) | 1 | pass,nolog | `tx.early_blocking` | 0 | - |
| [901120](901120.md) | 1 | pass,nolog | `tx.blocking_paranoia_level` | 1 | - |
| [901125](901125.md) | 1 | pass,nolog | `tx.detection_paranoia_level` | `%{TX.blocking_paranoia_level}` | - |
| [901130](901130.md) | 1 | pass,nolog | `tx.sampling_percentage` | 100 | - |
| [901140](901140.md) | 1 | pass,nolog | `tx.critical_anomaly_score` | 5 | - |
| [901141](901141.md) | 1 | pass,nolog | `tx.error_anomaly_score` | 4 | - |
| [901142](901142.md) | 1 | pass,nolog | `tx.warning_anomaly_score` | 3 | - |
| [901143](901143.md) | 1 | pass,nolog | `tx.notice_anomaly_score` | 2 | - |
| [901160](901160.md) | 1 | pass,nolog | `tx.allowed_methods` | `GET HEAD POST OPTIONS` | - |
| [901162](901162.md) | 1 | pass,nolog | `tx.allowed_request_content_type` | urlencoded/multipart/xml/json | - |
| [901163](901163.md) | 1 | pass,nolog | `tx.allowed_http_versions` | HTTP/1.0/1.1/2/2.0/3/3.0 | - |
| [901164](901164.md) | 1 | pass,nolog | `tx.restricted_extensions` | `.ani/ ... .xsx/` | - |
| [901165](901165.md) | 1 | pass,nolog | `tx.restricted_headers_basic` | content-encoding, proxy, ... | - |
| [901167](901167.md) | 1 | pass,nolog | `tx.enforce_bodyproc_urlencoded` | 0 | - |
| [901168](901168.md) | 1 | pass,nolog | `tx.allowed_request_content_type_charset` | utf-8, iso-8859-1/15, windows-1252 | - |
| [901169](901169.md) | 1 | pass,nolog | `tx.crs_validate_utf8_encoding` | 1 | - |
| [901170](901170.md) | 1 | pass,nolog | `tx.crs_skip_response_analysis` | 0 | - |
| [901171](901171.md) | 1 | pass,nolog | `tx.restricted_headers_extended` | `/accept-charset/` | - |
| [901510](901510.md) | 1 | pass,nolog | `tx.allow_method_override_parameter` | 0 | - |

- `&TX:변수 @eq 0` 조건은 **"변수가 아직 설정되지 않았을 때만"** 기본값을 넣는 idiom 이다.
  → `crs-setup.conf` 에서 사용자가 값을 지정하면 이 파일은 덮어쓰지 않는다.
- `901001` 은 유일하게 차단(500)하는 룰이며, setup 미로드(설정 오류)를 감지한다.

### 2.2 내부 변수 / 컬렉션 초기화

| ID | phase | action | 설명 |
|----|-------|--------|------|
| [901200](901200.md) | 1 | SecAction | 어노말리/공격별 스코어 변수를 0 으로 초기화 (blocking/detection inbound/outbound, pl1~4, sql/xss/rfi/lfi/rce/php/http_violation/session_fixation 등) |
| [901320](901320.md) | 1 | pass,nolog | `ENABLE_DEFAULT_COLLECTIONS=1` 일 때 GLOBAL/IP 컬렉션 생성. 기본 비활성 |

- 901200 은 조건 없는 `SecAction` 이므로 항상 실행되며, 이름 그대로 스코어의 시작점을 0 으로 만든다.
- 901320 은 `tx.enable_default_collections=1`(crs-setup 900130) 일 때만 동작한다.

### 2.3 Body Processing 초기화

| ID | phase | action | 설명 |
|----|-------|--------|------|
| [901340](901340.md) | 1 | pass,nolog,noauditlog | `REQBODY_PROCESSOR` 가 URLENCODED/MULTIPART/XML/JSON 이 아니면 `ctl:forceRequestBodyVariable=On` |
| [901350](901350.md) | 1 | pass,nolog,noauditlog | `tx.enforce_bodyproc_urlencoded=1` 이면 body processor 를 URLENCODED 로 강제 |

- 둘 다 `nolog,noauditlog` 라 로그가 없다. 901340 의 효과는 REQUEST_BODY 강제 설정.
- 901350 은 900010(`tx.enforce_bodyproc_urlencoded`) 활성화 시에만 동작.

### 2.4 샘플링 (Easing In)

| ID | phase | action | 설명 |
|----|-------|--------|------|
| [901400](901400.md) | 1 | pass,nolog | `tx.sampling_percentage=100` 이면 `skipAfter:END-SAMPLING` 로 샘플링 블록 건너뜀 |
| [901410](901410.md) | 1 | pass,capture,nolog | `UNIQUE_ID` sha1 에서 난수 `TX.sampling_rnd100` 생성 |
| [901450](901450.md) | 1 | pass,log,noauditlog | 난수 < sampling_percentage 이면 `ctl:ruleRemoveByTag=OWASP_CRS` 로 CRS 비활성 |
| SecMarker | - | - | `END-SAMPLING` (샘플링 블록 끝 표식) |

- 기본값 100 에서는 901400 이 블록을 건너뛰어 901410/901450 이 실행되지 않는다.

### 2.5 설정 정합성 검사

| ID | phase | action | 설명 |
|----|-------|--------|------|
| [901500](901500.md) | 1 | deny(500) | `detection_paranoia_level < blocking_paranoia_level` 이면 차단(잘못된 설정) |

## 3. 검증 (테스트 하네스)

`tests/` 디렉토리에 룰 id 기반 검증 스크립트가 있다.

```
tests/
├── lib.sh            # 공용 라이브러리 (probe/로그/nginx 제어)
├── verify.sh         # 룰 id -> 검증 케이스 레지스트리 (핵심)
├── run-all.sh        # 전체 실행 -> logs/run-all.log
├── 901001.sh ... 901510.sh   # 룰 id 이름의 개별 검증 스크립트
└── logs/<rule-id>.log        # 룰별 실행 결과 + 근거 로그
```

### 검증 방식

| 룰 유형 | 방법 |
|---------|------|
| `nolog` 변수 세팅 룰 (901100~901510 다수) | 테스트 전용 probe 룰(9900001)이 TX 변수 값을 error log 로 출력 → 기대값 비교 |
| 로그/차단 룰 (901001, 901500) | 별도 설정 인스턴스 기동 → HTTP 코드 + 감지 로그 확인 |
| `nolog/noauditlog` 룰 (901340) | `SecDebugLogLevel 9` 디버그 로그로 룰 평가 확인 |
| 기본 비활성 룰 (901320, 901350, 901410, 901450) | SKIP (활성화 조건 명시) |

probe 는 `Host: localhost` 로 요청해 룰 920350(Host numeric IP) 점수 오염을 피한다.

### 실행 방법

```bash
cd rules/REQUEST-901-INITIALIZATION/tests

./run-all.sh          # 전체
./901120.sh           # 특정 룰만
./verify.sh 901001 901500
```

### 현재 결과

```
PASS=32  FAIL=0  SKIP=4
```

- **SKIP 4건 사유**
  - `901320` — `tx.enable_default_collections=0` 이라 컬렉션 초기화 비활성
  - `901350` — `tx.enforce_bodyproc_urlencoded=0` 이라 body processor 강제 비활성
  - `901410` / `901450` — `sampling_percentage=100` 이라 901400 이 샘플링 블록을 skip
  - 활성화(각 crs-setup 옵션 ON) 후 별도 검증 가능

### 로그 출력 위치

스크립트가 생성하는 로그는 프로젝트 루트의 **임시 테스트 전용 디렉토리**
`logs/local_test/REQUEST-901-INITIALIZATION/` 에 모은다(삭제하지 않고 보존).

| 파일 | 내용 |
|------|------|
| `logs/local_test/REQUEST-901-INITIALIZATION/run-all.log` | 전체 실행 로그 |
| `logs/local_test/REQUEST-901-INITIALIZATION/<rule-id>.log` | 룰별 결과 + 근거(PROBE/LOG) |
| `logs/local_test/REQUEST-901-INITIALIZATION/nginx-error.log` | 테스트 nginx error log |
| `logs/local_test/REQUEST-901-INITIALIZATION/nginx-audit.log` | 테스트 audit log (probe 트랜잭션 포함) |
| `logs/local_test/REQUEST-901-INITIALIZATION/nginx-nosetup-audit.log` | 901001(설정 누락) audit log |
| `logs/local_test/REQUEST-901-INITIALIZATION/nginx-invalidpl-audit.log` | 901500(PL 오류) audit log |
| `logs/local_test/REQUEST-901-INITIALIZATION/nginx-901340-{error,audit,debug}.log` | 901340 (디버그/감사) |

> 생성되는 테스트 설정(`install/nginx/conf/crs-test-*.conf`)과 pid 는 실행 후 정리된다.
> 로그만 `logs/local_test/` 에 남는다.

테스트 설정은 테스트 전용 audit 로깅을 사용한다. `modsecurity.conf` 의
`SecAuditEngine RelevantOnly`(=로깅 룰이 매칭된 트랜잭션만 기록) 대신 `On` 으로 덮어써
**매칭되지 않는 요청(정적 200, 404 probe 등)까지 모두** audit 로그에 남긴다.

```
SecAuditEngine On
SecAuditLog <install>/logs/crs-test-audit.log
SecAuditLogType Serial
SecAuditLogParts ABIJDEFHZ
```

audit 로그는 트랜잭션 단위로 `---<id>---A--`, `---<id>---B--`, ... `---<id>---Z--` 섹션을 갖는다.
예: 901001 테스트의 audit 로그 H(메시지) 섹션에 `Access denied with code 500 (phase 1) ... [id "901001"]`.

> 참고: `901xxx` 초기화 룰 자체는 대부분 `nolog` 라 로그가 남지 않는다(의도된 동작).
> "로그가 안 남는" 것처럼 보였던 주된 원인은 (1) 901 룰의 `nolog`, (2) 종료 시 테스트 로그 파일 삭제,
> (3) audit 로그가 공용 파일로 가서 테스트 전용 로그가 없었던 점이다. 현재는 로그를 보존한다.

### 로그 예시

`logs/901001.log` (설정 오류 감지):
```
PASS 901001: setup 누락 감지 차단 (HTTP 500)
LOG ... ModSecurity: Access denied with code 500 (phase 1).
    Matched "Operator `Eq' ... against variable `TX:crs_setup_version' (Value: `0') ...
    [id "901001"] ...
```

`logs/901120.log` (probe 로 변수 확인):
```
PROBE ... [msg "CRS_PROBE:setup=4300:...:blocking_pl=1:detection_pl=1:..."]
PASS 룰 901120: blocking_pl 초기화 (blocking_pl=1)
```

## 4. 참고

- `SecComponentSignature` / `SecMarker` 는 룰 id 가 없다.
- 룰 id 대역 `901xxx` 는 CRS 의 초기화 예약 대역이다.
- 다음 분석 대상 후보: `REQUEST-905-COMMON-EXCEPTIONS.conf`, `REQUEST-920-PROTOCOL-ENFORCEMENT.conf`
- 환경 구성: [../../docs/environment/01-source-build.md](../../docs/environment/01-source-build.md)
