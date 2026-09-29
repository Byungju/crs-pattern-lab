# modsecurity.conf Directive 분석

분석 대상: `install/nginx/conf/modsecurity.conf`
(원본: `src/ModSecurity/modsecurity.conf-recommended` + `setup-config.sh` 로컬 오버라이드)

> 이 문서는 설정 파일에 실제로 존재하는 **directive 와 내장 룰**을 분석한다.
> 파일 끝의 `Include` (CRS 로더) 부분은 다루지 않는다. → 다음 문서에서 진행.

## 0. 개요

이 파일은 세 부분으로 구성된다.

1. `modsecurity.conf-recommended` 원문 그대로 (엔진/본문/응답/감사 로그 설정)
2. 그 안의 일부 directive 를 덮어쓰는 **로컬 오버라이드** (`setup-config.sh` 가 append)
3. CRS `Include` (이 문서 범위 밖)

특히 감사 로그 관련 directive 는 **1번과 2번에 중복 정의**되어 있고,
ModSecurity 는 **나중에 나온 값이 이긴다(last wins)**. 따라서 실제 적용값은
2번 오버라이드 값이다.

## 1. 실제 적용값(effective) 요약

| Directive | 적용값 | 위치 | 비고 |
|-----------|--------|------|------|
| `SecRuleEngine` | `On` | 원문 수정 | `DetectionOnly` → `On` |
| `SecRequestBodyAccess` | `On` | 원문 | |
| `SecRequestBodyLimit` | `13107200` (12.5 MB) | 원문 | |
| `SecRequestBodyNoFilesLimit` | `131072` (128 KB) | 원문 | |
| `SecRequestBodyLimitAction` | `Reject` | 원문 | DetectionOnly 시 자동 `ProcessPartial` |
| `SecRequestBodyJsonDepthLimit` | `512` | 원문 | |
| `SecArgumentsLimit` | `1000` | 원문 | |
| `SecPcreMatchLimit` | `1000` | 원문 | ReDoS 방지 |
| `SecPcreMatchLimitRecursion` | `1000` | 원문 | ReDoS 방지 |
| `SecResponseBodyAccess` | `On` | 원문 | |
| `SecResponseBodyMimeType` | `text/plain text/html text/xml` | 원문 | |
| `SecResponseBodyLimit` | `524288` (512 KB) | 원문 | |
| `SecResponseBodyLimitAction` | `ProcessPartial` | 원문 | |
| `SecTmpDir` | `/tmp/` | 원문 | |
| `SecDataDir` | `/tmp/` | 원문 | 영구 컬렉션 저장 |
| `SecAuditEngine` | `RelevantOnly` | 오버라이드 | |
| `SecAuditLogRelevantStatus` | `^(?:5\|4(?!04))` | 오버라이드 | 5xx + 4xx(404 제외) |
| `SecAuditLogParts` | `ABIJDEFHZ` | 오버라이드 | |
| `SecAuditLogType` | `Serial` | 오버라이드 | |
| `SecAuditLog` | `<install>/logs/modsecurity_audit.log` | 오버라이드 | 원문 `/var/log/modsec_audit.log` |
| `SecDebugLog` | `<install>/logs/modsecurity_debug.log` | 오버라이드 | |
| `SecDebugLogLevel` | `0` | 오버라이드 | 디버그 로그 비활성 |
| `SecArgumentSeparator` | `&` | 원문 | |
| `SecCookieFormat` | `0` | 원문 | |
| `SecUnicodeMapFile` | `unicode.mapping 20127` | 원문 | 파일명은 conf 디렉토리 기준 |
| `SecStatusEngine` | `Off` | 원문 | |

> `<install>` = `/home/ubuntu/web_security/install/nginx`

## 2. 엔진 초기화

### `SecRuleEngine On`
- **구문**: `SecRuleEngine On | Off | DetectionOnly` / **컨텍스트**: main / **엔진 기본값**: `Off`
- 트랜잭션에 ModSecurity 룰 엔진을 연결한다.
  - `Off`: 엔진 비활성 (룰 평가 안 함)
  - `DetectionOnly`: 룰은 평가하지만 **차단 동작(deny)을 수행하지 않고 로그만** 남긴다.
  - `On`: 매칭된 `disruptive action` 을 실제로 수행(차단)한다.
- 여기서는 권장 원문 `DetectionOnly` 를 `On` 으로 바꿔 **차단 모드**로 운영한다.
- CRS 관점: CRS 룰은 `blocking` 동작을 위해 `SecRuleEngine On` 을 전제로 한다.
  초기 도입/튜닝 단계에서는 `DetectionOnly` 로 FP 를 관찰한 뒤 `On` 으로 전환하는 것이 정석.

## 3. 요청 본문(request body) 처리

### `SecRequestBodyAccess On`
- **구문**: `SecRequestBodyAccess On | Off` / **기본값**: `Off`
- `On` 이면 요청 본문을 버퍼링하여 `ARGS_POST`, `REQUEST_BODY`, `FILES` 등을 룰에서 검사할 수 있다.
- `Off` 이면 POST 파라미터를 볼 수 없어 큰 보안 사각지대가 된다. CRS 필수.

### 내장 룰 200000 / 200001 — 본문 프로세서 활성화
```
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
  "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
  "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
```
- `Content-Type` 을 보고 **XML/JSON 파서를 지연 활성화**한다. 공격이 아니라 파싱 준비용 룰이다.
- `phase:1`(요청 헤더 단계)에서 `ctl:requestBodyProcessor=XML|JSON` 로 프로세서를 지정한다.
- XML 대상: `application/xml`, `application/soap+xml`, `text/xml`
- JSON 대상: `application/json` (하위 `+json` 서브타입은 주석 처리된 **200006** 참고)
- `pass` + `nolog` 이므로 점수/차단에 영향을 주지 않는다.
- CRS 관점: JSON/XML 파서가 켜져야 CRS 의 JSON/XML 관련 탐지(`REQUEST_BODY`, `ARGS`)가 동작한다.

### `SecRequestBodyLimit 13107200`
- 본문 **버퍼링 최대 크기**(바이트). 초과 시 `SecRequestBodyLimitAction` 적용.
- 파일 업로드를 지원하면 "가장 큰 업로드 파일 크기" 이상으로 잡아야 한다.
- 값: `13107200` = 12.5 MiB (12,800 KiB)

### `SecRequestBodyNoFilesLimit 131072`
- **파일 업로드 데이터를 제외한** 본문 최대 크기. 파일당이 아니라 파일 외 데이터 합계.
- 작게 유지하는 것이 좋다. 값: `131072` = 128 KiB

### `SecRequestBodyLimitAction Reject`
- **구문**: `Reject | ProcessPartial` / **기본값**: `Reject`
- 본문이 한도를 넘을 때:
  - `Reject`: 요청을 즉시 거부
  - `ProcessPartial`: 부분 처리 후 통과
- `SecRuleEngine DetectionOnly` 이면 자동으로 `ProcessPartial` 로 강제된다(차단 모드가 아니므로).
- CRS 관점: `Reject` 는 큰 본문을 악용한 메모리 고갈/우회 시도를 차단할 수 있으나,
  정상 대용량 업로드도 막을 수 있으므로 한도 튜닝이 필요하다.

### `SecRequestBodyJsonDepthLimit 512`
- JSON 중첩 깊이 최대값. 깊은 중첩을 파싱하다 자원을 소모하는 공격(JSON bomb)을 완화.
- 값 `512` 는 권장값이며, 필요 이상으로 크게 잡지 않는다.

### `SecArgumentsLimit 1000`
- 요청당 최대 인자(arguments) 수. 초과 시 **부분 파싱**만 이루어진다.
- 아래 룰 200007 의 조건값(`@ge 1000`)과 **값을 일치**시켜야 한다.

### 내장 룰 200007 — 인자 수 초과 시 거부
```
SecRule &ARGS "@ge 1000" "id:'200007', phase:2,t:none,log,deny,status:400,
  msg:'Failed to fully parse request body due to large argument count',severity:2"
```
- `&ARGS` 는 **ARGS 컬렉션의 개수**를 뜻한다. 1000 이상이면 차단(HTTP 400).
- `SecArgumentsLimit` 에 의해 파싱이 중단된 상태를 악용한 우회를 방지한다.

### 내장 룰 200002 — 본문 파싱 실패
```
SecRule REQBODY_ERROR "!@eq 0" "id:'200002', phase:2,t:none,log,deny,status:400,
  msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
```
- `REQBODY_ERROR` 는 본문 파싱 오류 코드(정상 0). 0이 아니면 차단.
- `logdata` 에 `reqbody_error_msg` 로 상세 원인을 기록한다.
- CRS 관점: 파서를 깨뜨려 검사를 우회하려는 시도를 차단하는 중요 방어선.

### 내장 룰 200003 — multipart 엄격 검증 실패
```
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:'200003',phase:2,t:none,log,deny,status:400,
  msg:'Multipart request body failed strict validation: PE %{REQBODY_PROCESSOR_ERROR}, ...'"
```
- `multipart/form-data` 파싱의 각종 이상 플래그(아래 변수) 중 하나라도 set 이면 차단.

| 약어 | 변수 | 의미 |
|------|------|------|
| PE | `REQBODY_PROCESSOR_ERROR` | 프로세서 오류 |
| BQ | `MULTIPART_BOUNDARY_QUOTED` | boundary 인용부호 문제 |
| BW | `MULTIPART_BOUNDARY_WHITESPACE` | boundary 공백 문제 |
| DB | `MULTIPART_DATA_BEFORE` | boundary 이전 데이터 |
| DA | `MULTIPART_DATA_AFTER` | 종료 boundary 이후 데이터 |
| HF | `MULTIPART_HEADER_FOLDING` | 헤더 folding |
| LF | `MULTIPART_LF_LINE` | LF 만 사용한 라인 |
| SM | `MULTIPART_MISSING_SEMICOLON` | 세미콜론 누락 |
| IQ | `MULTIPART_INVALID_QUOTING` | 잘못된 quoting |
| IP | `MULTIPART_INVALID_PART` | 비정상 part |
| IH | `MULTIPART_INVALID_HEADER_FOLDING` | 잘못된 헤더 folding |
| FL | `MULTIPART_FILE_LIMIT_EXCEEDED` | 파일 크기 한도 초과 |

### 내장 룰 200004 — multipart boundary 불일치 (strict)
```
SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" "id:'200004',phase:2,t:none,log,deny,
  msg:'Multipart parser detected a possible unmatched boundary.'"
```
- `MULTIPART_UNMATCHED_BOUNDARY` 값 의미:
  - `0`: 모든 boundary 라인이 정상
  - `1`: 필수 라인 누락/순서 오류 → **차단(strict)**
  - `2`: `--` 로 시작하는 추가 라인이 존재
- 위 설정은 `@eq 1` 만 차단하는 **permissive 모드**에 해당한다.
  (`@eq 1` 대신 `!@eq 0` 를 쓰면 `2` 까지 차단하는 strict 모드)
- permissive 를 쓰면 PEM(`----BEGIN...`) 이나 헤더가 포함된 텍스트 파일 업로드가 허용된다.

### `SecPcreMatchLimit 1000` / `SecPcreMatchLimitRecursion 1000`
- 룰 정규식 엔진(PCRE)의 **매치 횟수/재귀 깊이 한도**. 정규식 기반 DoS(ReDoS) 완화 목적.
- 한도를 넘으면 `TX.MSC_PCRE_LIMITS_EXCEEDED` 플래그가 set 되고, 아래 200005 가 차단한다.
- 주의: 값을 너무 낮추면 복잡한 정상 요청에서 FP(차단)가 날 수 있다.

### 내장 룰 200005 — 내부 오류 플래그 검사
```
SecRule TX:/^MSC_/ "!@streq 0" "id:'200005',phase:2,t:none,log,deny,
  msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"
```
- `MSC_` 로 시작하는 모든 TX 변수(예: `MSC_PCRE_LIMITS_EXCEEDED`)를 검사한다.
- `TX:/정규식/` 은 **이름이 정규식에 매칭되는 TX 컬렉션 전체**를 대상으로 하는 문법이다.
- 값이 문자열 `"0"` 이 아니면(=플래그 set) 차단하고, `MATCHED_VAR_NAME` 으로 원인 변수명을 남긴다.

## 4. 응답 본문(response body) 처리

### `SecResponseBodyAccess On`
- **기본값**: `Off`
- `On` 이면 응답 본문을 버퍼링해 데이터 유출/에러 노출을 검사한다.
- **메모리 사용량과 응답 지연이 증가**한다.
- CRS 관점: `RESPONSE-95x`(데이터 유출), `RESPONSE-98x`(상관관계) 룰이 동작하려면 필요.

### `SecResponseBodyMimeType text/plain text/html text/xml`
- 검사할 응답 MIME 타입 목록. 이미지/압축 파일 등 정적 리소스는 제외해 오버헤드를 줄인다.
- 기본값도 동일 계열이며, `application/json` 등을 추가할 수 있다.
- (`SecResponseBodyMimeTypesClear` 로 초기화 후 재정의 가능 — 이 파일에는 없음)

### `SecResponseBodyLimit 524288`
- 버퍼링할 응답 본문 최대 크기. 값: `524288` = 512 KiB

### `SecResponseBodyLimitAction ProcessPartial`
- 한도 초과 시 동작:
  - `ProcessPartial`: 가진 만큼만 검사하고 나머지는 그대로 전달 (기본값, 호환성 우선)
  - `Reject`: 응답을 거부
- `ProcessPartial` 은 정상 페이지를 깨지 않지만, 큰 응답의 뒷부분은 검사되지 않는다.

## 5. 파일시스템 / 업로드 설정

### `SecTmpDir /tmp/`
- 업로드 임시 파일 등 ModSecurity 임시 파일 위치.
- `/tmp` 는 모든 사용자가 쓸 수 있는 공용 디렉토리라 보안상 권장되지 않는다.
  → 전용 디렉토리(예: `install/nginx/var/tmp`)로 바꾸는 것이 좋다.

### `SecDataDir /tmp/`
- **영구 컬렉션(persistent collections)** 저장 위치. IP/세션 기반 룰이 여기에 데이터를 남긴다.
- 현재도 공용 `/tmp` 이므로 전용 디렉토리로 분리 권장.
- CRS 관점: IP reputation, DoS(DOS-PROTECTION) 등 컬렉션 기반 룰에 영향.
- 관련 directive `SecCollectionTimeout`(컬렉션 만료 시간)는 **이 파일에 명시되어 있지 않다**(엔진 기본값 사용).

### 주석 처리(비활성)된 업로드 설정
- `#SecUploadDir ...` : 업로드 파일 보관 디렉토리
- `#SecUploadKeepFiles RelevantOnly` : 검사에서 "의심"으로 판단된 파일만 보관
- `#SecUploadFileMode 0600` : 보관 파일 권한
- 업로드 파일 검사/보관을 하려면 활성화하고 디렉토리를 **ModSecurity 전용**으로 둔다.

## 6. 감사 로그(audit log) 설정

> 원문 값 뒤에 `setup-config.sh` 로컬 오버라이드가 중복 정의되어 있으며,
> 실제 적용값은 **오버라이드** 쪽이다.

### `SecAuditEngine RelevantOnly` (오버라이드)
- **구문**: `On | Off | RelevantOnly`
- `RelevantOnly`: `SecAuditLogRelevantStatus` 에 매칭되거나, 룰에서 `auditlog` action 이 걸린
  트랜잭션만 감사 로그에 기록한다.
- 전량(`On`) 로깅은 디스크/성능 부담이 크므로 보통 `RelevantOnly` 를 쓴다.

### `SecAuditLogRelevantStatus "^(?:5|4(?!04))"` (오버라이드)
- 감사 로그에 남길 응답 상태코드 정규식.
- `5xx` 전체, `4xx` 중 **404 제외**를 기록한다. (404 는 스캐너로 인한 노이즈가 많아 제외)

### `SecAuditLogParts ABIJDEFHZ` (오버라이드)
- 감사 로그에 포함할 섹션. (주로 A~K, Z)

| 파트 | 의미 |
|------|------|
| A | Audit log header (기본 정보) |
| B | Request headers |
| C | Request body (full) — **미포함** |
| D | Intermediary response headers |
| E | Intermediary response body |
| F | Final response headers |
| G | Final response body — **미포함** |
| H | Audit log trailer |
| I | Request body — reduced/alternative (multipart 제외) |
| J | Multipart 파일 정보 |
| K | 매칭된 룰 목록 |
| Z | 로그 종료 boundary |

- `C`(전체 본문), `G`(최종 응답 본문)는 빠져 있고 `I`·`J` 로 대체 본문 정보를 남긴다.
- `K` 도 빠져 있어 "매칭 룰 목록" 섹션은 별도로 포함되지 않는다
  (매칭 상세는 각 룰 메시지/error 로그로 확인).

### `SecAuditLogType Serial` (오버라이드)
- **구문**: `Serial | Concurrent | ...`
- `Serial`: 모든 트랜잭션을 **단일 파일**에 순차 기록. 열람은 쉽지만 동시성이 낮다.
- `Concurrent`: `SecAuditLogStorageDir` 에 트랜잭션별 파일로 기록. 대량 트래픽에 적합.
- 현재는 소규모 분석 환경에 맞는 `Serial` + 단일 파일 사용.

### `SecAuditLog <install>/logs/modsecurity_audit.log` (오버라이드)
- Serial 감사 로그 파일 경로. 원문 `/var/log/modsec_audit.log` → 랩 내부 경로로 변경.
- 로그 확인:
  ```bash
  grep -o '\[id "[0-9]*"\]' install/nginx/logs/modsecurity_audit.log | sort | uniq -c
  ```
- `Concurrent` 사용 시 대신 `SecAuditLogStorageDir` 를 지정한다(이 파일에는 미사용/주석).

## 7. 디버그 로그(debug log) 설정

### `SecDebugLog <install>/logs/modsecurity_debug.log` (오버라이드)
- 디버그 로그 파일 경로. (`#SecDebugLog ...` 원문은 주석 상태)

### `SecDebugLogLevel 0` (오버라이드)
- **구문**: `SecDebugLogLevel 0..9` / `0` = 로깅 안 함.
- 레벨이 높을수록 상세(및 성능 비용)가 커진다. 룰 디버깅 시에만 일시적으로 올린다.
- 현재 `0` 이므로 디버그 로그는 사실상 비활성이다.

## 8. 기타(miscellaneous)

### `SecArgumentSeparator &`
- `application/x-www-form-urlencoded` 에서 파라미터 구분자. 관례상 `&` 유지.

### `SecCookieFormat 0`
- 쿠키 포맷 버전. `0` = Netscape/일반 포맷. 잘못된 값을 쓰면 쿠키 대상 룰의 우회 가능.

### `SecUnicodeMapFile unicode.mapping 20127`
- `t:urlDecodeUni` 변환 시 사용할 유니코드 매핑 파일과 코드페이지.
- **경로가 상대경로(`unicode.mapping`)** 이므로 설정 로드 시 conf 디렉토리 등에서 파일을 찾는다.
  파일이 없으면 엔진 시작이 실패한다(실제로 겪음). `install/nginx/conf/unicode.mapping` 에 배치되어 있다.
- 코드페이지 `20127` = US-ASCII.

### `SecStatusEngine Off`
- 엔진/의존성 버전 정보를 외부로 전송하는 기능. 2022년 4월 이후 수신자가 없어 이득이 없으므로 `Off`.

## 9. 누락 / 미설정 / 주의 사항

- **`SecDefaultAction` 없음**: 기본 동작(disruptive action)은 CRS `crs-setup.conf` 에서 설정한다
  (phase 1/2 = `log,auditlog,pass` 등). → Include 분석 문서에서 다룸.
- **`SecCollectionTimeout` 없음**: 영구 컬렉션 만료는 엔진 기본값을 따른다.
- **`SecTmpDir` / `SecDataDir` = `/tmp/`**: 공용 디렉토리. 프로덕션에서는 전용 경로 권장.
- **감사 로그 `Serial`**: 단일 파일 동시 쓰기. 대량 트래픽에서는 `Concurrent` 검토.
- **`SecResponseBodyAccess On`**: 지연/메모리 비용 증가. outbound CRS 룰 사용 시 필요.
- **내장 룰 id 대역 200000~200007**: ModSecurity 권장 설정이 사용하는 예약 대역.
  CRS 는 9xxxxx 대역을 사용하므로 서로 충돌하지 않는다.

## 10. 참조

- ModSecurity Reference Manual (v3.x): <https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)>
- 원본 파일: `src/ModSecurity/modsecurity.conf-recommended`
- 환경 구성 문서: [../../docs/environment/01-source-build.md](../../docs/environment/01-source-build.md)
