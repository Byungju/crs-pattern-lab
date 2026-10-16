# CRS 공격 분류 · 근거 (OWASP 2025 / CWE / CAPEC / CVE)

> 각 룰 문서의 **「분류 / 근거」** 섹션에서 이 문서를 참조한다.
> OWASP 기준은 **OWASP Top 10:2025**, 공격 분류는 CRS 룰의 `attack-*` 태그, `capec/*`는 CRS가 룰에 직접 붙인 근거다.
>
> 2025 주요 변경: Injection 계열이 **A05:2025 – Injection** 으로, SSRF는 **단독 항목에서 제외되어 A01 – Broken Access Control** 로 흡수, Authentication은 **A07:2025 – Authentication Failures**.

---

## 0. 한눈에 보는 표

| CRS 태그 | 공격 명칭 | CWE | OWASP Top 10:2025 | CAPEC(대표) | CVE 예시 |
|----------|-----------|-----|-------------------|-------------|----------|
| `attack-sqli` | SQL Injection | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | A05 Injection | CAPEC-66 | CVE-2017-8917 |
| `attack-xss` | Cross-Site Scripting | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | A05 Injection | CAPEC-63 | CVE-2020-11022/11023 |
| `attack-rce` | Remote Code/Command Execution | [CWE-77](https://cwe.mitre.org/data/definitions/77.html)/[78](https://cwe.mitre.org/data/definitions/78.html)/[94](https://cwe.mitre.org/data/definitions/94.html) | A05 Injection | CAPEC-248/88 | CVE-2021-44228, CVE-2017-5638, CVE-2021-22205 |
| `attack-injection-php` | PHP Code Injection | CWE-94 | A05 Injection | CAPEC-242 | — |
| `attack-injection-java` | Java Code/Expression Injection | CWE-94 | A05 Injection | CAPEC-242 | — |
| `attack-injection-generic` | Code/Expression Injection | CWE-94 | A05 Injection | CAPEC-242 | — |
| `attack-ssti` | Server-Side Template Injection | CWE-1336/94 | A05 Injection | — | — |
| `attack-lfi` | Local File Inclusion | [CWE-98](https://cwe.mitre.org/data/definitions/98.html)/[22](https://cwe.mitre.org/data/definitions/22.html) | A05 Injection | CAPEC-126 | — |
| `attack-rfi` | Remote File Inclusion | CWE-98 | A05 Injection | CAPEC-253 | — |
| `attack-ssrf` | Server-Side Request Forgery | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | A01 Broken Access Control (SSRF 흡수) | CAPEC-664 | CVE-2021-26855 |
| `attack-fixation` | Session Fixation | [CWE-384](https://cwe.mitre.org/data/definitions/384.html) | A07 Authentication Failures | CAPEC-61 | — |
| `attack-disclosure` | Information Disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | A01 Broken Access Control (맥락) | CAPEC-116 | — |
| `attack-protocol` | Protocol Abuse (요청 스머글링 등) | [CWE-444](https://cwe.mitre.org/data/definitions/444.html)/[436](https://cwe.mitre.org/data/definitions/436.html) | 직접 대응 없음 (A02/A05 맥락) | CAPEC-272/33 | CVE-2019-16869, CVE-2020-8287, CVE-2021-40346 |
| `attack-multipart-header` | Multipart/Content-Disposition 파싱 우회 | CWE-436 | 직접 대응 없음 | CAPEC-33 | — |
| `attack-reputation-scanner` | 스캐너·자동화 도구 탐지(Reputation) | — | — | — | — |
| `attack-deprecated-header` | 폐기된(deprecated) 헤더 사용 | — | — | — | — |
| `attack-generic` | 일반/기타 공격 | — | — | — | — |

> CVE는 **해당 분류의 대표 사례**일 뿐, 특정 CVE 하나가 이 룰에 대응하는 것은 아니다.
> CVE 번호는 공개 자료 기준 예시이며, 룰 자체는 **공격 기법(클래스)** 을 탐지한다.

---

## 1. 주요 분류 설명

### SQL Injection (`attack-sqli`)
- 사용자 입력이 SQL로 해석되어 인증 우회·데이터 유출·변조를 유발. CWE-89, OWASP **A05:2025 Injection**.
- CRS: [REQUEST-942](../rules/REQUEST-942-APPLICATION-ATTACK-SQLI/README.md) (통합 SQLi 룰 + libinjection).
- 대표: CVE-2017-8917(Joomla!).

### Cross-Site Scripting (`attack-xss`)
- 입력이 브라우저에서 스크립트로 실행(Saved/Reflected/DOM). CWE-79, OWASP **A05:2025 Injection**.
- CRS: [REQUEST-941](../rules/REQUEST-941-APPLICATION-ATTACK-XSS/README.md) (libinjection `@detectXSS` 포함).
- 대표: CVE-2020-11022/11023(jQuery).

### Remote Code/Command Execution (`attack-rce`)
- 명령·코드·표현식이 실행됨(OS command, lang eval, deserialization 등). CWE-77/78/94, OWASP **A05:2025 Injection**.
- CRS: [REQUEST-932](../rules/REQUEST-932-APPLICATION-ATTACK-RCE/README.md)(명령), [933](../rules/REQUEST-933-APPLICATION-ATTACK-PHP/README.md)(PHP), [944](../rules/REQUEST-944-APPLICATION-ATTACK-JAVA/README.md)(Java/Log4Shell 등).
- 대표: CVE-2021-44228(Log4Shell), CVE-2017-5638(Struts2), CVE-2021-22205(GitLab).

### File Inclusion (`attack-lfi`/`attack-rfi`)
- 경로/URL로 로컬·원격 파일을 include/읽기 → 코드 실행·정보 유출. CWE-98/22, OWASP **A05:2025 Injection**.
- CRS: [REQUEST-930](../rules/REQUEST-930-APPLICATION-ATTACK-LFI/README.md), [REQUEST-931](../rules/REQUEST-931-APPLICATION-ATTACK-RFI/README.md).

### SSRF (`attack-ssrf`)
- 서버가 공격자 지정 URL로 요청 → 내부망 접근·메타데이터 탈취. CWE-918.
- OWASP Top 10:2025에서는 **SSRF가 단독 항목에서 제외**되어 **A01 – Broken Access Control** 로 다룬다.
- CRS: [REQUEST-934](../rules/REQUEST-934-APPLICATION-ATTACK-GENERIC/README.md) (generic 계열).
- 대표: CVE-2021-26855(Exchange ProxyLogon).

### Protocol Abuse (`attack-protocol`)
- 요청 스머글링/Desync, 응답 분할, Range DoS 등 파서 불일치·프로토콜 악용. CWE-444/436.
- CRS: [REQUEST-920](../rules/REQUEST-920-PROTOCOL-ENFORCEMENT/README.md), [REQUEST-921](../rules/REQUEST-921-PROTOCOL-ATTACK/README.md).
- 개념: [request-smuggling.md](request-smuggling.md). 대표: CVE-2021-40346(HAProxy), CVE-2011-3192(Range DoS).

### Session Fixation (`attack-fixation`)
- 세션 ID를 공격자가 미리 고정 → 로그인 후 탈취. CWE-384, OWASP **A07:2025 Authentication Failures**.
- CRS: [REQUEST-943](../rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION/README.md).

### Information Disclosure (`attack-disclosure`)
- 응답/에러/헤더로 내부 정보 노출. CWE-200, OWASP **A01:2025 Broken Access Control** 맥락.
- CRS: [RESPONSE-950](../rules/RESPONSE-950-DATA-LEAKAGES/README.md) ~ [956](../rules/RESPONSE-956-DATA-LEAKAGES-RUBY/README.md).

---

## 2. 참고

- OWASP Top 10:2025: <https://owasp.org/Top10/2025/>
- CWE: <https://cwe.mitre.org/> · CAPEC: <https://capec.mitre.org/>
- 실행 모델/점수: [execution-model.md](execution-model.md) · [score-and-paranoia.md](score-and-paranoia.md)
