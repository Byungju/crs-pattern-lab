# REQUEST-920-PROTOCOL-ENFORCEMENT.conf — 쉽게 읽는 분석

> 이 문서는 **HTTP 프로토콜 위반 탐지** 파일을 "기초 → 룰 → 공격 예제 → 흐름 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 "무엇을(변수) / 어떻게(연산자)" 검사하고 "무엇을 할지(action)" 정한다.
  여기서는 `REQUEST_LINE`, `REQUEST_HEADERS:*`, `REQUEST_METHOD`, `ARGS` 등을 검사한다.
- **phase**: 1=요청 헤더, 2=요청 본문. 이 파일은 두 phase 모두 사용한다.
- **어노말리 스코어**: 룰은 즉시 막지 않고 점수만 쌓고, phase 2 끝에 `949110` 이 임계값(5)을 넘으면 403.
  - CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2
  - 그래서 NOTICE/WARNING 룰은 **단독으로는 403 이 안 날 수 있다.**
- **paranoia level(PL)**: 1~4. 구간 사이에 게이팅 룰(`92xxx` 8개)이 있다.

> 기초: [REQUEST-911 README](../REQUEST-911-METHOD-ENFORCEMENT/README.md),
> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> **HTTP 규약을 어긴 요청(헤더/본문/인자/Content-Type 등)을 탐지해, 정책 위반이면 403으로 차단한다.**

---

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [920011](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [920012](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [920100](920100.md) | 1 | 1 | WARNING | Invalid HTTP Request Line |
| [920120](920120.md) | 2 | 1 | CRITICAL | Attempted multipart/form-data bypass |
| [920160](920160.md) | 1 | 1 | CRITICAL | Content-Length HTTP header is not numeric |
| [920170](920170.md) | 1 | 1 | CRITICAL | GET or HEAD Request with Body Content |
| [920171](920171.md) | 1 | 1 | CRITICAL | GET or HEAD Request with Transfer-Encoding |
| [920180](920180.md) | 1 | 1 | WARNING | POST without Content-Length and Transfer-Encoding headers |
| [920181](920181.md) | 1 | 1 | WARNING | Content-Length and Transfer-Encoding headers present |
| [920190](920190.md) | 1 | 1 | WARNING | Range: Invalid Last Byte Value |
| [920660](920660.md) | 1 | 1 | WARNING | Obsolete Request-Range header detected |
| [920210](920210.md) | 1 | 1 | WARNING | Multiple/Conflicting Connection Header Data Found |
| [920250](920250.md) | 2 | 1 | WARNING | UTF8 Encoding Abuse Attack Attempt |
| [920260](920260.md) | 2 | 1 | WARNING | Unicode Full/Half Width Abuse Attack Attempt |
| [920270](920270.md) | 2 | 1 | CRITICAL | Invalid character in request (null character) |
| [920280](920280.md) | 1 | 1 | CRITICAL | Request Missing a Host Header |
| [920290](920290.md) | 1 | 1 | CRITICAL | Empty Host Header |
| [920310](920310.md) | 1 | 1 | NOTICE | Request Has an Empty Accept Header |
| [920311](920311.md) | 1 | 1 | NOTICE | Request Has an Empty Accept Header |
| [920330](920330.md) | 1 | 1 | NOTICE | Empty User Agent Header |
| [920340](920340.md) | 1 | 1 | CRITICAL | Content-Type header missing from request with non-zero Content-Length |
| [920350](920350.md) | 1 | 1 | WARNING | Host header is a numeric IP address |
| [920380](920380.md) | 2 | 1 | CRITICAL | Too many arguments in request |
| [920360](920360.md) | 2 | 1 | CRITICAL | Argument name too long |
| [920370](920370.md) | 2 | 1 | CRITICAL | Argument value too long |
| [920390](920390.md) | 2 | 1 | CRITICAL | Total arguments size exceeded |
| [920400](920400.md) | 1 | 1 | CRITICAL | Uploaded file size too large |
| [920410](920410.md) | 2 | 1 | CRITICAL | Total uploaded files size too large |
| [920470](920470.md) | 1 | 1 | CRITICAL | Illegal Content-Type header |
| [920420](920420.md) | 1 | 1 | CRITICAL | Request content type is not allowed by policy |
| [920480](920480.md) | 1 | 1 | CRITICAL | Request content type charset is not allowed by policy |
| [920530](920530.md) | 1 | 1 | CRITICAL | Multiple charsets detected in content type header |
| [920640](920640.md) | 2 | 1 | CRITICAL | Content-Type header missing from request with body |
| [920430](920430.md) | 1 | 1 | CRITICAL | HTTP protocol version is not allowed by policy |
| [920440](920440.md) | 1 | 1 | CRITICAL | URL file extension is restricted by policy |
| [920500](920500.md) | 1 | 1 | CRITICAL | Attempt to access a backup or working file |
| [920450](920450.md) | 1 | 1 | CRITICAL | HTTP header is restricted by policy (%{MATCHED_VAR}) |
| [920520](920520.md) | 1 | 1 | CRITICAL | Accept-Encoding header exceeded sensible length |
| [920600](920600.md) | 1 | 1 | CRITICAL | Illegal Accept header: charset parameter |
| [920539](920539.md) | 2 | - | - |  |
| [920540](920540.md) | 2 | 1 | CRITICAL | Possible Unicode character bypass detected |
| [920610](920610.md) | 1 | 1 | CRITICAL | Raw (unencoded) fragment in request URI |
| [920620](920620.md) | 1 | 1 | CRITICAL | Multiple Content-Type Request Headers |
| [920013](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [920014](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [920200](920200.md) | 1 | 2 | WARNING | Range: Too many fields (6 or more) |
| [920201](920201.md) | 1 | 2 | WARNING | Range: Too many fields for pdf request (63 or more) |
| [920230](920230.md) | 2 | 2 | WARNING | Multiple URL Encoding Detected |
| [920271](920271.md) | 2 | 2 | CRITICAL | Invalid character in request (non printable characters) |
| [920320](920320.md) | 1 | 2 | NOTICE | Missing User Agent Header |
| [920121](920121.md) | 2 | 2 | CRITICAL | Attempted multipart/form-data bypass |
| [920451](920451.md) | 1 | 2 | CRITICAL | HTTP header is restricted by policy (%{MATCHED_VAR}) |
| [920240](920240.md) | 2 | 2 | WARNING | URL Encoding Abuse Attack Attempt |
| [920650](920650.md) | 2 | 2 | CRITICAL | HTTP method override attempt via _method parameter |
| [920015](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [920016](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [920272](920272.md) | 2 | 3 | CRITICAL | Invalid character in request (outside of printable chars below ascii 127) |
| [920300](920300.md) | 1 | 3 | NOTICE | Request Missing an Accept Header |
| [920490](920490.md) | 1 | 3 | CRITICAL | Request header x-up-devcap-post-charset detected in combination with prefix \ |
| [920510](920510.md) | 1 | 3 | CRITICAL | Invalid Cache-Control request header |
| [920521](920521.md) | 1 | 3 | CRITICAL | Illegal Accept-Encoding header |
| [920017](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [920018](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [920202](920202.md) | 1 | 4 | WARNING | Range: Too many fields for pdf request (6 or more) |
| [920273](920273.md) | 2 | 4 | CRITICAL | Invalid character in request (outside of very strict set) |
| [920274](920274.md) | 1 | 4 | CRITICAL | Invalid character in request headers (outside of very strict set) |
| [920275](920275.md) | 1 | 4 | CRITICAL | Invalid character in request headers (outside of very strict set) |
| [920460](920460.md) | 2 | 4 | CRITICAL | Abnormal character escapes in request |

---

## 3. 공격 예제 및 실측

이 환경(nginx + libmodsecurity v3)에서 **트리거 가능한** 룰의 공격 예제와 결과다.

| ID | 공격 예제(요청) | HTTP | 비고 |
|----|------------------|------|------|
| [920100](920100.md) | `TOOLONGMETHODX / HTTP/1.1` (11자 이상 메서드) | **403** | 잘못된 요청 라인 |
| [920120](920120.md) | multipart `filename="a;b.txt"` (구분자 문자) | **403** | multipart 우회 |
| [920280](920280.md) | `GET / HTTP/1.0` (Host 헤더 없음) | **403** | Host 누락 |
| [920330](920330.md) | `User-Agent:` (빈 값) | 200 | NOTICE=2 → 단독 차단 안 됨 |
| [920350](920350.md) | `Host: 127.0.0.1` (숫자 IP) | 200 | WARNING=3 → 단독 차단 안 됨 |
| [920420](920420.md) | `Content-Type: text/plain` + body | **403** | 정책 외 Content-Type |
| [920440](920440.md) | `GET /x.bak` | **403** | 금지 확장자 |
| [920450](920450.md) | `Proxy: 1` 헤더 | **403** | 금지 헤더 |
| [920480](920480.md) | `Content-Type: application/json; charset=utf-16` | **403** | 정책 외 charset |
| [920600](920600.md) | `Accept: text/html; charset=foo-bar` | **403** | 잘못된 Accept charset |
| [920620](920620.md) | `Content-Type` 헤더 2개 | **403** | 중복 Content-Type |

> 나머지 룰은 **nginx 가 ModSecurity(CRS) 도달 전에 400/405 로 먼저 막거나**, 특정 설정/조건
> (인자 수 제한, 업로드 크기, multipart 등)이 필요해 이 환경에서 자동 트리거가 어렵다.
> 해당 룰은 `tests/<id>.sh` 에서 SKIP(사유 표기) 처리했다.
>
> **예외**: `920100`은 대부분의 잘못된 요청 라인을 nginx가 400으로 먼저 막지만,
> **11자 이상 메서드**(예: `TOOLONGMETHODX / HTTP/1.1`)처럼 nginx가 통과시키면서 RFC 형식을
> 벗어나는 경우에는 실제로 발동한다(403 + `[id "920100"]` 로그).

> **"nginx 도달 불가"의 의미**: CRS 룰(예: `920100`)이 **실행되지 않는다**는 뜻이다.
> 이때도 **nginx 자체 로그는 남는다.**
> - `logs/local_test/REQUEST-920-PROTOCOL-ENFORCEMENT/nginx-error.log`:
>   `client sent invalid request while reading client request line` (ModSecurity id 없음)
> - `logs/local_test/REQUEST-920-PROTOCOL-ENFORCEMENT/nginx-access.log`:
>   `"GET /\x01 HTTP/1.1" 400`
>
> 즉 "CRS 로그 없음"과 "nginx 로그 없음"은 다르다.

---

## 4. 흐름 / 관계

```
요청 도착
  phase 1 : 헤더/요청라인 관련 룰 (920100, 920280, 920350, 920420, 920440, 920450 ...)
            → 매칭된 룰이 점수 누적
  phase 2 : 본문/인자 관련 룰 (920270, 920380, 920400, 920480 ...)
  phase 2 끝 : 949110 이 누적 점수 >= 임계값(5) 이면 403 차단
```

- 파일은 PL 구간으로 나뉘고, 구간 사이 게이팅 룰(`920011`~`920018`)이
  "PL이 낮으면 끝으로 점프" 하며 하위 PL 구간을 건너뛴다.
- 실제 차단은 **`949110`(다른 파일)** 이 수행한다. 920 룰은 "탐지 + 점수" 담당.

---

## 5. 검증 (테스트 하네스)

```
tests/
├── lib.sh        # 테스트 nginx 기동, curl/raw(nc) 요청, 룰 id 카운트
├── verify.sh     # 룰 id별 검증 케이스
├── run-all.sh    # 전체 실행
├── 920xxx.sh     # 룰 id별 개별 실행
└── (로그: ../../../logs/local_test/REQUEST-920-PROTOCOL-ENFORCEMENT/)
```

```bash
cd rules/REQUEST-920-PROTOCOL-ENFORCEMENT/tests
./run-all.sh        # 전체
./920420.sh         # 개별
```

현재 결과(이 환경):
```
PASS=16  FAIL=0  SKIP=51
```
- 구현된 9개 룰(920280/330/350/420/440/450/480/600/620)은 PASS.
- 나머지는 SKIP(nginx 도달불가/조건필요). (게이팅 룰 8개는 테스트에서 제외)

로그: `logs/local_test/REQUEST-920-PROTOCOL-ENFORCEMENT/` (룰별 `.log`, `nginx-error.log`, `nginx-audit.log`)

---

## 6. 용어 미니 사전

| 용어 | 뜻 |
|------|-----|
| `REQUEST_LINE` | 요청 첫 줄 (`GET / HTTP/1.1`) |
| `REQUEST_HEADERS:*` | 특정 요청 헤더 값 |
| `ARGS` / `ARGS_NAMES` | (쿼리/본문) 파라미터 값 / 이름 |
| 어노말리 스코어 | 룰이 쌓는 위험 점수, 임계값 넘으면 `949110`이 차단 |
| paranoia level(PL) | 룰 민감도 단계(1~4) |
| `skipAfter` / `SecMarker` | 표식까지 건너뛰기 / 그 목적지 |

---

## 7. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- `crs-setup.conf` 정책 변수(인자 제한 등): [../../modsecurity/base-rules/crs-setup-conf.md](../../modsecurity/base-rules/crs-setup-conf.md)
- 유사 파일: [REQUEST-911](../REQUEST-911-METHOD-ENFORCEMENT/README.md), [REQUEST-913](../REQUEST-913-SCANNER-DETECTION/README.md)
