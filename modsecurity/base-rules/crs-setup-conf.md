# crs-setup.conf Directive 분석 (기본룰)

분석 대상: `install/nginx/conf/crs/crs-setup.conf`
(원본: `coreruleset/crs-setup.conf.example`, CRS **4.30.0-dev**)

> 이 문서는 CRS 의 **설정 파일(crs-setup.conf)** 을 분석한다. 실제 탐지 룰 파일
> (`rules/*.conf`)과 ModSecurity 엔진 설정(`modsecurity.conf`)은 별도 문서에서 다룬다.

## 0. 개요

`crs-setup.conf` 는 CRS 룰이 동작하는 데 필요한 **정책 변수(tx 변수)와 기본 동작**을
정의하는 파일이다. 파일 대부분(약 928줄 중 14줄만 활성)이 주석으로 된 **튜닝 옵션
카탈로그**이며, 실제로 활성화된 것은 다음 두 가지뿐이다.

| 라인 | 활성 directive | 역할 |
|------|----------------|------|
| 97–101 | `SecDefaultAction` (phase 1~5) | 룰의 기본(disruptive) 동작 = pass |
| 920–928 | `SecAction` id `900990` | `tx.crs_setup_version=4300` 설정 |

나머지 `#SecAction ...` 블록들은 **주석 상태의 선택적 튜닝 옵션**으로,
기본값이 아니거나 사이트 정책에 맞게 바꿀 때 주석을 해제한다.

### 로드 순서

CRS 문서가 요구하는 include 순서는 다음과 같다.

```
1. modsecurity.conf      (엔진 설정)
2. crs-setup.conf        (이 파일, CRS 정책 변수)
3. rules/*.conf          (실제 탐지 룰)
```

### 기본 동작 모드: Anomaly Scoring

- CRS 4는 **Anomaly Scoring(이상 점수) 모드**가 기본이다.
- 개별 룰은 매칭 시 즉시 차단하지 않고 `pass` + 점수 누적(`tx.inbound_anomaly_score` 등)만 한다.
- phase 2(요청) / phase 4(응답) 종료 시 점수를 임계값과 비교해
  `REQUEST-949-BLOCKING-EVALUATION.conf` / `RESPONSE-959-...` 가 **403 차단**을 수행한다.
- 반대로 Self-Contained 모드는 룰이 즉시 차단(deny)하며, crs-setup 에서
  `SecDefaultAction "...,deny"` 로 바꾸면 된다(주석 예시 존재).

## 1. 활성 Directive

### `SecDefaultAction` (phase 별, 라인 97–101)

```
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
SecDefaultAction "phase:3,log,auditlog,pass"
SecDefaultAction "phase:4,log,auditlog,pass"
SecDefaultAction "phase:5,log,auditlog,pass"
```

- **의미**: `SecDefaultAction` 은 룰이 별도 disruptive action 을 지정하지 않았을 때
  상속되는 기본 동작이다. 여기서는 phase 별로 동일하게 설정한다.
- **`pass`**: 매칭돼도 요청을 막지 않고 다음 룰 평가를 계속한다 → 점수 누적 방식의 핵심.
- **`log`**: 웹서버 error log 에 기록.
- **`auditlog`**: ModSecurity 감사 로그에 기록(`SecAuditEngine`/`SecAuditLogParts` 영향).
- **phase 1~5 를 모두 지정**하는 이유: CRS 룰은 여러 phase 에 분포하므로
  각 phase 의 기본 동작을 명시적으로 통일한다.
- 로깅 변형(주석 예시):
  - `nolog,auditlog` : 감사 로그에만 기록
  - `log,noauditlog` : error log 에만 기록
- Self-Contained 로 바꾸려면 `pass` → `deny` (주석 예시 참고). `deny` 는 기본 403.

### `SecAction` id `900990` — setup 버전 표식 (라인 920)

```
SecAction \
    "id:900990,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.30.0-dev',\
    setvar:tx.crs_setup_version=4300"
```

- `SecAction` 은 조건 없이 항상 실행되는 액션 룰이다(operator 없음).
- `tx.crs_setup_version=4300` : CRS 4.30.0 을 숫자 `major*1000+minor*10`? 형식으로 표기.
  (예: v3.0.0 → 300, v4.30.0 → 4300)
- `REQUEST-901-INITIALIZATION.conf` 의 룰이 이 변수가 0인지 검사하여,
  **crs-setup 을 로드하지 않았으면 경고/중단**한다. 즉 이 룰이 setup 로드 증표다.
- `phase:1`(요청 시작 전)에서 `nolog` 로 조용히 실행된다.

## 2. 선택적 튜닝 옵션 (주석, 기본 비활성)

아래 블록들은 모두 주석 처리되어 있으며, 필요 시 주석을 해제한다.
**대부분의 기본값은 `REQUEST-901-INITIALIZATION.conf` 가 변수가 비어 있을 때 설정**한다
(즉 crs-setup 에서 지정하지 않으면 901의 기본값 적용).

### 2.1 Paranoia Level (PL)

| id | 변수 | 기본값 | 설명 |
|----|------|--------|------|
| `900000` | `tx.blocking_paranoia_level` | 1 | 차단(점수 반영) 기준 PL. 1~4. 높을수록 룰 많고 FP 증가 |
| `900001` | `tx.detection_paranoia_level` | =blocking | 탐지 전용 PL. blocking 보다 낮을 수 없음 |

- PL 별 태그: 감사 로그에 `[tag "paranoia-level/N"]` 로 표시된다.
- `detection_paranoia_level > blocking_paranoia_level` 이면 상위 PL 룰도 **평가만** 하고
  점수에는 반영하지 않는다(점진적 상향 튜닝용, 성능 비용 동일).

### 2.2 Body Processor 강제 / 점수 / 임계값

| id | 변수 | 기본값 | 설명 |
|----|------|--------|------|
| `900010` | `tx.enforce_bodyproc_urlencoded` | 0(off) | Content-Type 없을 때 URLENCODED 파서 강제. CRS 우회 차단(FP 위험) |
| `900100` | `tx.critical_anomaly_score` | 5 | CRITICAL severity 점수 |
| `900100` | `tx.error_anomaly_score` | 4 | ERROR severity (주로 95x outbound) |
| `900100` | `tx.warning_anomaly_score` | 3 | WARNING severity (주로 91x) |
| `900100` | `tx.notice_anomaly_score` | 2 | NOTICE severity (주로 92x) |
| `900110` | `tx.inbound_anomaly_score_threshold` | 5 | 인바운드 차단 임계값 |
| `900110` | `tx.outbound_anomaly_score_threshold` | 4 | 아웃바운드 차단 임계값 |

- 기본 임계값(5/4)에서는 **critical 룰 1개 매칭만으로도 차단**될 수 있다.
- 임계값을 올리면 덜 민감해지지만 LFI/RFI/RCE/데이터유출 보호가 약화된다.
- 신규 도입 시 임계값을 100+ 로 시작해 점차 낮추는 전략도 가능.

### 2.3 Reporting / Early Blocking / Collections

| id | 변수 | 기본값 | 설명 |
|----|------|--------|------|
| `900115` | `tx.reporting_level` | 4 | phase5 상세 보고 수준 0~5 (0=비활성, 5=모든 요청) |
| `900120` | `tx.early_blocking` | 0(off) | phase1/3 종료 시 조기 차단. 뒤 phase 룰 평가가 생략될 수 있음 |
| `900130` | `tx.enable_default_collections` | 0(off) | Global/IP 컬렉션(플러그인용) 초기화 |

- `reporting_level` 값 의미: 1=차단 점수, 2=탐지 점수, 3=차단 점수>0, 4=탐지 점수>0, 5=전체.
- Nginx 처럼 access log 커스터마이즈가 어려운 환경에서 레벨 5가 유용.

### 2.4 HTTP 정책 (allowed/restricted)

| id | 변수 | 기본값 |
|----|------|--------|
| `900200` | `tx.allowed_methods` | `GET HEAD POST OPTIONS` |
| `900210` | `tx.allow_method_override_parameter` | (미설정=차단) |
| `900220` | `tx.allowed_request_content_type` | `\|application/x-www-form-urlencoded\| \|multipart/form-data\| \|text/xml\| \|application/xml\| \|application/soap+xml\| \|application/json\|` |
| `900230` | `tx.allowed_http_versions` | `HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0` |
| `900240` | `tx.restricted_extensions` | `.ani/ .asa/ ... .xsx/` (다수) |
| `900250` | `tx.restricted_headers_basic` | `/content-encoding/ /proxy/ /lock-token/ /content-range/ /if/ /x-http-method-override/ /x-http-method/ /x-method-override/ /x-middleware-subrequest/ /expect/` |
| `900255` | `tx.restricted_headers_extended` | `/accept-charset/` |
| `900280` | `tx.allowed_request_content_type_charset` | `\|utf-8\| \|iso-8859-1\| \|iso-8859-15\| \|windows-1252\|` |

- **`900200` allowed_methods**: PUT 은 기본 비활성(임의 업로드 위험). REST API 는 `PUT PATCH DELETE` 추가.
- **`900210` method override**: `_method` 파라미터 오버라이드 허용 여부.
  기본은 `_method` 사용을 PL2+ 에서 차단(CSRF/ACL 우회 방지). `X-HTTP-Method-Override`
  헤더는 별도 룰 `920450` 이 처리.
- **`900220` content-type**: `@within` 연산자(대소문자 구분, `t:lowercase` 사용)이므로
  **소문자 전체**로 지정해야 한다.
  `text/plain` 등 body processor 를 안 타는 content-type 을 허용하면
  JSON/XML 우회가 가능하다. 허용 시 반드시 대응 body parser 룰을 함께 추가한다.
- **`900230` http versions**: `HTTP/0.9` 는 RFC 9110 에서 폐기, 룰 `920100` 이 차단.
- **`900240` restricted_extensions**: 개발/설정 파일 노출 방지 목록.
  `.axd` 는 FP 로 제외됨. 압축 아카이브 확장자 추가 예시가 주석에 있음.
- **`900250` restricted_headers_basic**: `httpoxy`(`/proxy/`), method override,
  CVE-2025-29927(`/x-middleware-subrequest/`, Next.js), Expect 기반 desync(`/expect/`) 등 대응.
- **`900255` restricted_headers_extended**: `/accept-charset/` 등 FP 가능성이 있어 상위 PL 에서 차단.
- **`900280` charset**: 목록 추가 시 `regex-assembly` 재생성 필요. 잘못 추가하면 body 우회 위험.

### 2.5 Argument / Upload Limits (DoS 완화)

기본값은 모두 **unlimited**, 필요 시 활성화. `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` 에서 검사.

| id | 변수 | 예시값 | 설명 |
|----|------|--------|------|
| `900300` | `tx.max_num_args` | 255 | 인자 개수 상한 (엔진 `SecArgumentsLimit` 가 우선) |
| `900310` | `tx.arg_name_length` | 100 | 인자 이름 길이 상한 |
| `900320` | `tx.arg_length` | 400 | 인자 값 길이 상한 |
| `900330` | `tx.total_arg_length` | 64000 | 인자 전체 길이 상한 |
| `900340` | `tx.max_file_size` | 1048576 | 개별 업로드 파일 크기 상한 |
| `900350` | `tx.combined_file_sizes` | 1048576 | 전체 업로드 파일 크기 상한 |

### 2.6 Easing In / 샘플링

| id | 변수 | 기본값 | 설명 |
|----|------|--------|------|
| `900400` | `tx.sampling_percentage` | 100 | CRS 로 검사할 요청 비율(%, 의사난수) |

- 100 미만이면 일부 요청은 CRS 검사를 **완전히 우회**한다(보호 공백).
- 검사 제외 요청은 감사 로그가 아니라 error log 에만 남는다. `SecRuleUpdateActionById 901450 "nolog"` 로 끌 수 있다.

### 2.7 UTF-8 검사 / 응답 검사

| id | 변수 | 기본 동작 | 설명 |
|----|------|-----------|------|
| `900950` | `tx.crs_validate_utf8_encoding=0` | 검사 **활성** | 비활성화하려면 주석 해제. non-UTF-8 파라미터 사이트의 FP 완화 |
| `900500` | `tx.crs_skip_response_analysis=1` | 응답 검사 **활성** | 활성화하면 `RESPONSE-95x` 분석 생략. RFDoS(Response Filter DoS) 대응 |

- UTF-8 검사는 `REQUEST_FILENAME`, `ARGS`, `ARGS_NAMES` 대상.
- 응답 검사는 `SecResponseBodyAccess On` 필요. RFDoS 우려 시 `900500` 으로 생략.

## 3. tx 변수 기본값 요약 (crs-setup 미지정 시)

| 변수 | 기본값 | 설정 주체 |
|------|--------|-----------|
| `tx.crs_setup_version` | `4300` | **crs-setup (900990, 활성)** |
| `tx.blocking_paranoia_level` | `1` | 901-INITIALIZATION |
| `tx.detection_paranoia_level` | `=%{blocking}` | 901-INITIALIZATION |
| `tx.critical_anomaly_score` | `5` | 901-INITIALIZATION |
| `tx.error_anomaly_score` | `4` | 901-INITIALIZATION |
| `tx.warning_anomaly_score` | `3` | 901-INITIALIZATION |
| `tx.notice_anomaly_score` | `2` | 901-INITIALIZATION |
| `tx.inbound_anomaly_score_threshold` | `5` | 901-INITIALIZATION |
| `tx.outbound_anomaly_score_threshold` | `4` | 901-INITIALIZATION |
| `tx.sampling_percentage` | `100` | 901-INITIALIZATION |
| `tx.allowed_methods` | `GET HEAD POST OPTIONS` | 901-INITIALIZATION |
| `tx.allowed_request_content_type` | (위 2.4 표) | 920-... |
| `tx.max_num_args` 등 limit | unlimited | (미설정) |

## 4. 참고 사항

- **id 대역 900000–900990**: CRS 의 "설정/초기화" 용도 예약 대역. 실제 탐지 룰(9xxxxx)과 구분된다.
- **`SecDefaultAction` vs `SecAction`**: 전자는 룰 기본 동작 상속, 후자는 조건 없는 단일 액션 룰.
- **대부분의 정책 변수는 901-INITIALIZATION 이 기본값을 채운다.** crs-setup 의 주석 블록은
  "기본값을 사이트 정책에 맞게 덮어쓰기" 위한 템플릿이다.
- 다음 분석 대상: `rules/*.conf` (특히 `REQUEST-901-INITIALIZATION.conf`, `REQUEST-949-BLOCKING-EVALUATION.conf`).

## 5. 참조

- 원본: `coreruleset/crs-setup.conf.example`
- CRS 문서: <https://coreruleset.org/docs/configuration/config/>, <https://coreruleset.org/docs/concepts/plugins/>
- 엔진 설정 분석: [modsecurity-conf.md](modsecurity-conf.md)
- 환경 구성: [../../docs/environment/01-source-build.md](../../docs/environment/01-source-build.md)
