# REQUEST-901-INITIALIZATION.conf — 쉽게 읽는 분석

> 이 문서는 CRS의 **초기화 파일**을, ModSecurity를 처음 보는 사람도 이해할 수 있도록
> "기초 → 이 파일의 역할 → 룰 → 흐름 → 검증" 순서로 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-901-INITIALIZATION.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

### (1) 룰(Rule)은 "무엇을(변수) / 어떻게(연산자)" 검사하고 "무엇을 할지(action)" 정한다

```
SecRule  TX:blocking_paranoia_level   "@eq 0"   "phase:1, pass, nolog, setvar:tx.blocking_paranoia_level=1"
        └─ 검사 대상(변수)              └─ 연산자  └─ 매칭 시 할 일(액션)
```

- **변수**: 요청/설정에서 꺼낸 값.
- **연산자**: 비교 방법. `@eq`(같다), `@lt`(작다), `@rx`(정규식), `@within`(목록 포함) 등.
- **액션**: 매칭 시 행동. `pass`(통과), `deny`(차단), `setvar`(값 설정), `nolog`(로그 안 남김) 등.

### (2) 처리는 "phase(단계)" 순서로 진행된다

| phase | 시점 |
|-------|------|
| **1** | 요청 **헤더** 직후 (메서드/경로/헤더) |
| **2** | 요청 **본문**까지 받은 뒤 |
| 3 / 4 | 응답 헤더 / 응답 본문 |
| 5 | 로깅 |

→ 이 파일의 룰은 **거의 모두 phase 1** 에서 실행된다(요청이 시작되기 전에 값부터 준비).

### (3) `tx.*` 는 요청마다 새로 만들어지는 임시 변수다

- CRS는 정책/점수를 `tx.` 변수에 담는다(예: `tx.allowed_methods`, `tx.inbound_anomaly_score_threshold`).
- 이 값은 **요청 1건 동안만** 유효하므로, **매 요청 시작 시점에 다시 준비**해야 한다.
- 그 "준비"를 하는 파일이 바로 **이 파일(901)** 이다.

### (4) CRS는 "어노말리 스코어" 방식으로 차단한다

- 탐지 룰은 **즉시 막지 않고 점수만 쌓고**, phase 2 끝에 `949110` 이 임계값을 넘으면 403을 낸다.
- 그래서 901은 점수 변수를 **0으로 초기화**해 두는 역할도 한다.

> 더 자세한 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> **901은 공격을 막는 파일이 아니다.**
> CRS가 제대로 동작하도록 **매 요청 시작 시 정책 변수/점수를 준비(초기화)** 하는 파일이며,
> 설정이 잘못됐으면 **`901001`(설정 누락) / `901500`(PL 설정 오류)이 500으로 막는다.**

---

## 2. 이 파일이 하는 일

1. **설정 로드 확인** — `crs-setup.conf` 가 로드됐는지 확인 (`901001`)
2. **기본값 채우기** — 정책 변수가 비었으면 안전한 기본값을 넣음 (`901100`~`901510`)
3. **점수/변수 초기화** — 어노말리 점수를 0으로, 컬렉션 초기화 (`901200`, `901320`)
4. **본문/샘플링 준비** — body processor 강제, 샘플링 결정 (`901340`~`901450`)
5. **설정 정합성 검사** — 잘못된 PL 설정 차단 (`901500`)

---

## 3. 룰

각 룰의 **상세 설명은 같은 폴더의 `<rule-id>.md`** 에 있다.
검증 스크립트는 `tests/<rule-id>.sh`.

### 3.1 설정 확인 / 기본값 채움

| ID | phase | action | 대상 변수 | 기본값 | 로그 |
|----|-------|--------|-----------|--------|------|
| [901001](901001.md) | 1 | deny(500) | `TX:crs_setup_version` | (없으면 차단) | log+auditlog |
| [901100](901100.md) | 1 | pass,nolog | `tx.inbound_anomaly_score_threshold` | 5 | - |
| [901110](901110.md) | 1 | pass,nolog | `tx.outbound_anomaly_score_threshold` | 4 | - |
| [901111](901111.md) | 1 | pass,nolog | `tx.reporting_level` | 4 | - |
| [901115](901115.md) | 1 | pass,nolog | `tx.early_blocking` | 0 | - |
| [901120](901120.md) | 1 | pass,nolog | `tx.blocking_paranoia_level` | 1 | - |
| [901125](901125.md) | 1 | pass,nolog | `tx.detection_paranoia_level` | =blocking | - |
| [901130](901130.md) | 1 | pass,nolog | `tx.sampling_percentage` | 100 | - |
| [901140](901140.md) | 1 | pass,nolog | `tx.critical_anomaly_score` | 5 | - |
| [901141](901141.md) | 1 | pass,nolog | `tx.error_anomaly_score` | 4 | - |
| [901142](901142.md) | 1 | pass,nolog | `tx.warning_anomaly_score` | 3 | - |
| [901143](901143.md) | 1 | pass,nolog | `tx.notice_anomaly_score` | 2 | - |
| [901160](901160.md) | 1 | pass,nolog | `tx.allowed_methods` | `GET HEAD POST OPTIONS` | - |
| [901162](901162.md) | 1 | pass,nolog | `tx.allowed_request_content_type` | urlencoded/multipart/xml/json | - |
| [901163](901163.md) | 1 | pass,nolog | `tx.allowed_http_versions` | HTTP/1.0~3.0 | - |
| [901164](901164.md) | 1 | pass,nolog | `tx.restricted_extensions` | `.ani/ ... .xsx/` | - |
| [901165](901165.md) | 1 | pass,nolog | `tx.restricted_headers_basic` | content-encoding, proxy, ... | - |
| [901167](901167.md) | 1 | pass,nolog | `tx.enforce_bodyproc_urlencoded` | 0 | - |
| [901168](901168.md) | 1 | pass,nolog | `tx.allowed_request_content_type_charset` | utf-8, iso-8859-1/15, windows-1252 | - |
| [901169](901169.md) | 1 | pass,nolog | `tx.crs_validate_utf8_encoding` | 1 | - |
| [901170](901170.md) | 1 | pass,nolog | `tx.crs_skip_response_analysis` | 0 | - |
| [901171](901171.md) | 1 | pass,nolog | `tx.restricted_headers_extended` | `/accept-charset/` | - |
| [901510](901510.md) | 1 | pass,nolog | `tx.allow_method_override_parameter` | 0 | - |

> **중요한 문법**: 조건이 `&TX:변수 @eq 0` 이다. 이는 "값이 0"이 아니라
> **"변수가 아직 없을 때만"** 이라는 뜻이다(변수 개수가 0).
> 그래서 `crs-setup.conf` 에서 사용자가 값을 정했으면 **이 파일은 덮어쓰지 않는다.**

### 3.2 내부 변수 / 컬렉션 초기화

| ID | phase | 설명 |
|----|-------|------|
| [901200](901200.md) | 1 | 어노말리/공격별 점수 변수를 **0으로 초기화** |
| [901320](901320.md) | 1 | `ENABLE_DEFAULT_COLLECTIONS=1` 일 때 GLOBAL/IP 컬렉션 생성 (기본 비활성) |

### 3.3 Body Processing 초기화

| ID | phase | 설명 |
|----|-------|------|
| [901340](901340.md) | 1 | 본문 프로세서가 미지원이면 `REQUEST_BODY` 강제 노출 |
| [901350](901350.md) | 1 | `tx.enforce_bodyproc_urlencoded=1` 이면 URLENCODED 로 강제 (기본 비활성) |

### 3.4 샘플링 (Easing In)

| ID | phase | 설명 |
|----|-------|------|
| [901400](901400.md) | 1 | `sampling_percentage=100` 이면 샘플링 블록 **건너뜀** |
| [901410](901410.md) | 1 | 난수 `TX.sampling_rnd100` 생성 |
| [901450](901450.md) | 1 | 난수가 비율보다 크면 **이 요청의 CRS를 끔** |
| SecMarker | - | `END-SAMPLING` (건너뛰기 목적지) |

### 3.5 설정 정합성 검사

| ID | phase | 설명 |
|----|-------|------|
| [901500](901500.md) | 1 | `detection_paranoia_level < blocking_paranoia_level` 이면 500 차단 (잘못된 설정) |

---

## 4. 흐름과 관계

### 4.1 파일 로드 순서 (중요)

```
modsecurity.conf      (엔진 설정)
   └─ crs-setup.conf  (정책 변수: 사용자가 바꾸는 곳)
        └─ 901-INITIALIZATION   ← 이 파일: 매 요청 값 준비
             └─ 나머지 rules/*.conf (실제 탐지 룰)
```

- 이 순서가 지켜지지 않으면(특히 `crs-setup.conf` 누락) **901001 이 500으로 막는다.**

### 4.2 요청 1건에서 901이 하는 일

```
요청 도착
  phase 1 · 901001  : crs-setup 로드됐나? (없으면 500)
  phase 1 · 901xxx  : 정책 변수가 비었으면 기본값 채움
  phase 1 · 901200  : 점수 변수 0으로 초기화
  phase 2~          : (이후 탐지 룰들이 이 값들을 사용)
```

### 4.3 이 파일이 준비한 값을 "누가 쓰는가"

| 준비하는 값 (룰) | 사용하는 곳 |
|------------------|-------------|
| `tx.allowed_methods` ([901160](901160.md)) | `REQUEST-911` (911100) |
| `tx.allowed_request_content_type` ([901162](901162.md)) | `REQUEST-920` |
| `tx.allowed_http_versions` ([901163](901163.md)) | `REQUEST-920` |
| `tx.restricted_extensions` ([901164](901164.md)) | `REQUEST-920` |
| `tx.restricted_headers_basic/extended` ([901165](901165.md)/[901171](901171.md)) | `REQUEST-920` |
| `tx.allowed_request_content_type_charset` ([901168](901168.md)) | `REQUEST-920`, `REQUEST-922` |
| `tx.allow_method_override_parameter` ([901510](901510.md)) | `REQUEST-920` |
| `tx.crs_validate_utf8_encoding` ([901169](901169.md)) | `REQUEST-920` |
| `tx.crs_skip_response_analysis` ([901170](901170.md)) | `RESPONSE-950` |
| `tx.inbound_anomaly_score_threshold` ([901100](901100.md)) | `REQUEST-949`, `RESPONSE-980` |
| `tx.outbound_anomaly_score_threshold` ([901110](901110.md)) | `RESPONSE-959`, `RESPONSE-980` |
| `tx.blocking_paranoia_level` ([901120](901120.md)) | `REQUEST-949` (PL별 점수 합산) |
| `tx.detection_paranoia_level` ([901125](901125.md)) | 거의 모든 `9xx`/`95x` 룰의 실행 게이트 |
| `tx.critical/error/warning/notice_anomaly_score` ([901140](901140.md)~[901143](901143.md)) | 모든 탐지 룰의 점수 |
| `tx.early_blocking` ([901115](901115.md)) | `REQUEST-949`, `RESPONSE-959` |
| `tx.reporting_level` ([901111](901111.md)) | `RESPONSE-980` |
| `tx.sampling_percentage` ([901130](901130.md)) | 이 파일의 901400/901450 |

즉, **901은 "다른 파일들이 쓰는 값"을 매 요청 준비해 주는 파일**이고, 그 자체로는 공격을 막지 않는다.

---

## 5. 검증 (테스트 하네스)

```
tests/
├── lib.sh            # 공용 라이브러리 (probe/로그/nginx 제어)
├── verify.sh         # 룰 id → 검증 케이스
├── run-all.sh        # 전체 실행
├── 901001.sh ... 901510.sh   # 룰 id 이름의 개별 검증 스크립트
└── (로그: ../../../logs/local_test/REQUEST-901-INITIALIZATION/)
```

### 검증 방식 (공격 payload가 아니라 "상태" 검증)

| 룰 유형 | 검증 방법 |
|---------|-----------|
| `nolog` 변수 룰 (다수) | 테스트 전용 probe 룰이 TX 값을 error log로 출력 → 기대값 비교 |
| 로그/차단 룰 (901001, 901500) | 별도 설정 인스턴스 기동 → HTTP 500 + 로그 확인 |
| `nolog/noauditlog` 룰 (901340) | `SecDebugLogLevel 9` 디버그 로그로 실행 확인 |
| 기본 비활성 룰 (901320/901350/901410/901450) | SKIP (활성화 조건 명시) |

### 실행

```bash
cd rules/REQUEST-901-INITIALIZATION/tests
./run-all.sh          # 전체
./901120.sh           # 특정 룰만
```

현재 결과: `PASS=32  FAIL=0  SKIP=4`
- SKIP 4건: `901320`, `901350`, `901410`, `901450` (각각 기본 설정에서 비활성)

### 로그 위치

스크립트 생성 로그는 `logs/local_test/REQUEST-901-INITIALIZATION/` 에 모아 보존한다.

| 파일 | 내용 |
|------|------|
| `run-all.log`, `<rule-id>.log` | 전체 / 룰별 결과 + 근거(PROBE/LOG) |
| `nginx-error.log`, `nginx-audit.log` | 테스트 nginx error / audit 로그 |
| `nginx-nosetup-*.log`, `nginx-invalidpl-*.log`, `nginx-901340-*.log` | 특수 케이스 로그 |

> 901 룰은 대부분 `nolog` 라 로그가 안 남는 게 정상이다. 그래서 probe/디버그로 확인한다.

---

## 6. 용어 미니 사전

| 용어 | 뜻 |
|------|-----|
| phase | 처리 단계 (1=요청헤더, 2=요청본문, 3/4=응답, 5=로깅) |
| action | 매칭 시 동작 (`pass`, `deny`, `block`, `setvar`, `nolog`, `chain`) |
| `tx.*` | 요청마다 초기화되는 임시 변수 |
| `&TX:변수` | 변수의 **개수**(없으면 0) — "설정됐는지" 확인용 |
| 어노말리 스코어 | 룰이 쌓는 위험 점수, 임계값 넘으면 `949110`이 차단 |
| paranoia level(PL) | 룰 민감도 단계(1~4) |
| `nolog` | error/audit 로그를 남기지 않음 |
| `SecAction` | 조건 없는(항상 실행되는) 액션 룰 |
| `SecMarker` / `skipAfter` | 건너뛰기 목적지 표식 / 그 표식까지 점프 |

---

## 7. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 다음 파일: [REQUEST-905-COMMON-EXCEPTIONS](../REQUEST-905-COMMON-EXCEPTIONS/README.md),
  [REQUEST-911-METHOD-ENFORCEMENT](../REQUEST-911-METHOD-ENFORCEMENT/README.md)
- `SecComponentSignature` / `SecMarker` 는 룰 id 가 없다.
- 환경 구성: [../../docs/environment/01-source-build.md](../../docs/environment/01-source-build.md)
