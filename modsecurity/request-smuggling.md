# HTTP Request Smuggling (요청 밀수) — 개념과 CRS 방어

> REQUEST-920의 CL/TE 관련 룰들이 "무엇을 막는지"의 공통 배경 문서.
> 각 룰 문서(`920160`/`920170`/`920171`/`920180`/`920181` …)에서 이 문서를 참조한다.

---

## 0. 한 줄 요약

프론트엔드 프록시와 백엔드 서버가 **요청의 본문 경계(길이)를 서로 다르게 해석**하는 틈을 이용해,
공격자가 **하나의 요청 뒤에 다른 요청을 몰래 끼워 넣는(smuggle)** 공격.

---

## 1. 왜 발생하나 (근본 원인)

HTTP/1.1에서 본문 길이는 두 헤더로 결정된다.

| 헤더 | 의미 |
|------|------|
| `Content-Length` (CL) | 본문 길이(바이트) |
| `Transfer-Encoding: chunked` (TE) | 청크 단위 길이 |

- **RFC 7230 §3.3.2**: 송신자는 **`Transfer-Encoding`이 있으면 `Content-Length`를 보내면 안 된다.**
- **RFC 7230 §3.3.3**(현 **RFC 9112 §6.1**): 수신자는 **TE가 있으면 CL을 무시**하고, 모호하면 오류로 처리해야 한다.
- 그런데 **구현체(프록시 vs 서버)마다** TE/CL 우선순위, 중복 헤더, 변형(예: `Transfer-Encoding : chunked`, 대소문자·공백·개행 난독화) 처리가 달라
  **파서 불일치(desync)** 가 생긴다. → 여기서 요청 경계가 어긋난다.

---

## 2. 대표 변종

| 변종 | 프론트(프록시) | 백엔드 | 결과 |
|------|----------------|--------|------|
| **CL.TE** | CL 사용 | TE 사용 | 잔여 바이트가 다음 요청 앞에 붙음 |
| **TE.CL** | TE 사용 | CL 사용 | 백엔드가 본문을 덜/더 소비 |
| **TE.TE** | 둘 다 TE | 난독화로 한쪽만 인식 | 한쪽이 무시 → 같은 효과 |
| **CL.0 / H2.CL / H2.TE** | HTTP/2 다운그레이드 등 | — | H2→H1 변환 시 발생 |

- **영향**: 캐시 오염(cache poisoning), 접근제어/인증 우회, 요청 하이재킹(request hijacking),
  저장형 XSS, WAF 우회.
- 공격자는 "다음 사용자의 요청"에 자신의 요청을 끼워 넣어 **피해자 권한으로 요청을 실행**시킬 수 있다.

---

## 3. 근거 자료

- **CWE-444** — *Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')*
- **CAPEC** — `capec/1000/210/272` (CRS 태그): Mechanism of Attack(1000) / Abuse of Functionality(210) / Protocol Manipulation(272)
- **표준** — RFC 7230 §3.3.2·§3.3.3, RFC 9110 §9.3.1(GET 본문), RFC 9112 §6.1(메시지 본문 처리)
- **OWASP** — WSTG의 "Testing for HTTP Request Smuggling" 항목. *(OWASP Top 10:2025에는 직접 항목이 없고, 맥락상 A05:2025–Injection·A02:2025–Security Misconfiguration로 언급된다.)*
- **공격 명칭** — "HTTP Request Smuggling", "HTTP Desync Attack"(2019, James Kettle) — 정식 명칭이 있으므로 이 이름으로 지칭.
- **CVE 예시**(서버/프록시 파서 불일치로 인한 실제 취약점):
  - CVE-2019-16869 — Netty (Transfer-Encoding 오처리)
  - CVE-2020-8287 — Node.js (llhttp, CL/TE 동시 처리)
  - CVE-2021-40346 — HAProxy (정수 오버플로 기반 request smuggling)
  - CVE-2021-22959 / CVE-2021-22960 — Node.js (llhttp)
  > 같은 계열 취약점이 여러 제품에서 반복 보고되어 왔다(목록은 예시).

---

## 4. CRS의 방어 룰 (REQUEST-920-METHOD... 아님, PROTOCOL-ENFORCEMENT)

| 룰 | 막는 요청 |
|----|-----------|
| [920160](../rules/REQUEST-920-PROTOCOL-ENFORCEMENT/920160.md) | `Content-Length` 값이 **숫자가 아님** |
| [920170](../rules/REQUEST-920-PROTOCOL-ENFORCEMENT/920170.md) | **GET/HEAD에 본문**(`Content-Length`≠0) |
| [920171](../rules/REQUEST-920-PROTOCOL-ENFORCEMENT/920171.md) | **GET/HEAD에 `Transfer-Encoding`** |
| [920180](../rules/REQUEST-920-PROTOCOL-ENFORCEMENT/920180.md) | HTTP/1.x **POST에 CL·TE 둘 다 없음**(본문 길이 불명) |
| [920181](../rules/REQUEST-920-PROTOCOL-ENFORCEMENT/920181.md) | **`Content-Length`와 `Transfer-Encoding` 동시 존재**(RFC 위반) |

- 이 룰들은 **어노말리 스코어**를 누적하고, phase 2 끝에서 `949110`이 임계값 초과 시 **403** 을 낸다.
- 관련: [921110](../rules/REQUEST-921-PROTOCOL-ATTACK/921110.md)(요청 스머글링 패턴), [921120](../rules/REQUEST-921-PROTOCOL-ATTACK/921120.md)·[921130](../rules/REQUEST-921-PROTOCOL-ATTACK/921130.md)(응답 분할).
- 점수/차단 연결: [score-and-paranoia.md](score-and-paranoia.md)

---

## 5. 실무 완화 (참고)

- 서버/프록시를 최신으로 유지(파서 일관성). 가능하면 **HTTP/2·HTTP/3** 사용.
- **모호한 요청 거부**: 중복/변형 `Content-Length`, `Transfer-Encoding`+`Content-Length` 동시, 비정상 청크.
- TE와 CL이 함께 오면 **연결을 닫는** 것이 표준 권장 동작.
- 프론트/백엔드 스택을 **동일 계열/버전**으로 맞춰 해석 차이를 줄인다.

---

## 6. 참고

- 실행 모델: [execution-model.md](execution-model.md)
- 점수/PL: [score-and-paranoia.md](score-and-paranoia.md)
- 게이팅: [paranoia-gating.md](paranoia-gating.md)
