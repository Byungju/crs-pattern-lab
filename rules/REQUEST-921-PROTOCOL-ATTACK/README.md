# REQUEST-921-PROTOCOL-ATTACK.conf — 쉽게 읽는 분석

> 이 문서는 **HTTP 프로토콜 공격 탐지** 파일을 "기초 → 룰 → 공격 예제 → 흐름 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `ARGS_NAMES`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝에 `949110` 이 임계값(5)을 넘으면 403. (이 파일의 탐지 룰은 거의 CRITICAL=5)
- **paranoia level(PL)**: 1~4. 이 파일은 **PL2~4 룰이 많다**.
- **`skipAfter` / `SecMarker`**: 게이팅 룰이 PL 구간을 건너뛸 때 사용.

> 기초: [REQUEST-911 README](../REQUEST-911-METHOD-ENFORCEMENT/README.md),
> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> **HTTP 프로토콜을 악용한 공격 패턴을 탐지한다.**
> (Header Injection, Response Splitting, Request Smuggling, Parameter Pollution, LDAP Injection 등)

---

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [921011](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [921012](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [921110](921110.md) | 2 | 1 | CRITICAL | HTTP Request Smuggling Attack |
| [921120](921120.md) | 2 | 1 | CRITICAL | HTTP Response Splitting Attack |
| [921130](921130.md) | 2 | 1 | CRITICAL | HTTP Response Splitting Attack |
| [921140](921140.md) | 1 | 1 | CRITICAL | HTTP Header Injection Attack via headers |
| [921150](921150.md) | 2 | 1 | CRITICAL | HTTP Header Injection Attack via payload (CR/LF detected) |
| [921160](921160.md) | 1 | 1 | CRITICAL | HTTP Header Injection Attack via payload (CR/LF and header-name detected) |
| [921190](921190.md) | 1 | 1 | CRITICAL | HTTP Splitting (CR/LF in request filename detected) |
| [921200](921200.md) | 2 | 1 | CRITICAL | LDAP Injection Attack |
| [921421](921421.md) | 1 | 1 | CRITICAL | Content-Type header: Dangerous content type outside the mime type declaration |
| [921240](921240.md) | 1 | 1 | CRITICAL | mod_proxy attack attempt detected |
| [921250](921250.md) | 1 | 1 | CRITICAL | Old Cookies V1 usage attempt detected |
| [921013](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [921014](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [921151](921151.md) | 1 | 2 | CRITICAL | HTTP Header Injection Attack via payload (CR/LF detected) |
| [921422](921422.md) | 1 | 2 | CRITICAL | Content-Type header: Dangerous content type outside the mime type declaration |
| [921015](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [921016](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [921230](921230.md) | 1 | 3 | CRITICAL | HTTP Range Header detected |
| [921170](921170.md) | 2 | - | - | (helper) |
| [921180](921180.md) | 2 | 3 | CRITICAL | HTTP Parameter Pollution (%{MATCHED_VAR_NAME}) |
| [921210](921210.md) | 2 | 3 | CRITICAL | HTTP Parameter Pollution after detecting bogus char after parameter array |
| [921017](../../modsecurity/paranoia-gating.md) | 1 | - | - | (게이팅) PL 구간 제어 |
| [921018](../../modsecurity/paranoia-gating.md) | 2 | - | - | (게이팅) PL 구간 제어 |
| [921220](921220.md) | 2 | 4 | CRITICAL | HTTP Parameter Pollution possible via array notation |

---

## 3. 공격 예제 및 실측

테스트는 **detection/blocking PL=4** 로 설정해 모든 PL 룰을 실행/차단한다.
(실제 배포 기본은 PL1)

| ID | 공격 예제(요청) | HTTP | 유형 |
|----|------------------|------|------|
| [921110](921110.md) | `/?x=GET / http/1.1` | **403** | Request Smuggling |
| [921120](921120.md) | `/?x=foo%0d%0aset-cookie:%20abc` | **403** | Response Splitting |
| [921130](921130.md) | `/?x=<html>` | **403** | Response Splitting |
| [921150](921150.md) | `/?a%0d%0ab=1` (param name CRLF) | **403** | Header Injection |
| [921151](921151.md) | `/?x=foo%0d%0aBar:baz` (param value CRLF) | **403** | Header Injection (PL2) |
| [921160](921160.md) | `/?x=foo%0d%0aset-cookie:%20abc` | **403** | Header Injection |
| [921180](921180.md) | `/?a=1&a=2` | **403** | Parameter Pollution (PL3) |
| [921190](921190.md) | `/foo%0aBar` (path CRLF) | **403** | Splitting |
| [921200](921200.md) | `/?q=*)(uid=*)(|(cn=*` | **403** | LDAP Injection |
| [921220](921220.md) | `/?a[]=1&a[]=2` | **403** | HPP array (PL4) |
| [921230](921230.md) | `Range: bytes=0-1` | **403** | Range Header (PL3) |
| [921240](921240.md) | `/?x=unix:/tmp/sock|` | **403** | mod_proxy |
| [921250](921250.md) | `Cookie: $Version=1; a=b` | **403** | Old Cookies V1 |
| [921421](921421.md) | `Content-Type: x application/json` | **403** | Dangerous CT |
| [921422](921422.md) | `Content-Type: application/x-www-form-urlencoded;application/xml` | **403** | Dangerous CT (PL2) |

> 도달 불가/미구현: `921140`(헤더에 CRLF → nginx 가 먼저 거부), `921210`(특정 디코딩 필요),
> `921170`(921180 의 전구 helper, nolog), 게이팅 8개.

---

## 4. 흐름 / 관계

```
요청 도착
  phase 1 : 921140/921160/921190/921240/921250, 921421/921422 (헤더/경로/Content-Type)
  phase 2 : 921110/921120/921130/921150/921151/921200 (파라미터/쿠키/본문)
            921170(helper: ARGS_NAMES 카운트) → 921180 (HPP)
  phase 2 끝 : 949110 이 누적 점수 >= 임계값(5) 이면 403
```

- CRLF(개행) 기반 공격(Header Injection/Splitting)과 파라미터 오염(HPP)이 핵심이다.
- 실제 차단은 **`949110`(다른 파일)** 이 수행한다.

---

## 5. 검증 (테스트 하네스)

```
tests/
├── lib.sh        # 테스트 nginx 기동(PL4), curl 요청, 룰 id 카운트
├── verify.sh     # 룰 id별 검증 케이스
├── run-all.sh    # 전체 실행
├── 921xxx.sh     # 룰 id별 개별 실행
└── (로그: ../../../logs/local_test/REQUEST-921-PROTOCOL-ATTACK/)
```

```bash
cd rules/REQUEST-921-PROTOCOL-ATTACK/tests
./run-all.sh       # 전체
./921120.sh        # 개별
```

현재 결과: `PASS=30  FAIL=0  SKIP=3`
- 구현 15개 룰 → 403 차단 + 로그 확인.
- SKIP 3 = 921140/921210/921170. (게이팅 룰 8개는 테스트에서 제외)

로그: `logs/local_test/REQUEST-921-PROTOCOL-ATTACK/`

---

## 6. 용어 미니 사전

| 용어 | 뜻 |
|------|-----|
| Header Injection | 헤더에 CR/LF 를 넣어 헤더/응답을 조작 |
| Response Splitting | CR/LF 로 응답을 쪼개는 공격 |
| Request Smuggling | CL/TE 등으로 요청 경계를 혼동시키는 공격 |
| HPP | HTTP Parameter Pollution (파라미터 중복/배열) |
| `ARGS` / `ARGS_NAMES` | 파라미터 값 / 이름 |
| `REQUEST_FILENAME` | URL 경로(디코딩된 파일명) |
| `skipAfter` / `SecMarker` | 표식까지 건너뛰기 / 그 목적지 |

---

## 7. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 유사 파일: [REQUEST-920](../REQUEST-920-PROTOCOL-ENFORCEMENT/README.md), [REQUEST-922](../REQUEST-922-MULTIPART-ATTACK/README.md)
