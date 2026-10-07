# crs-pattern-lab

## 목적

이 프로젝트는 **OWASP ModSecurity Core Rule Set(CRS)** 과 **ModSecurity directive**를
분석하고, 각 룰에 대응하는 **공격 예제(payload/pattern)** 를 수집·검증하여
"룰 → 공격 예제 → 탐지 로그"를 한 곳에 정리하는 것을 목적으로 한다.

- 분석 대상 룰셋: <https://github.com/coreruleset/coreruleset>
- 분석 대상 엔진/디렉티브: <https://github.com/owasp-modsecurity/ModSecurity> 및
  nginx 커넥터 <https://github.com/owasp-modsecurity/ModSecurity-nginx>
- 검증 환경: nginx + libmodsecurity(v3) + ModSecurity-nginx + OWASP CRS

즉, 단순히 룰을 나열하는 것이 아니라 **"이 룰이 어떤 요청을, 어떤 조건으로,
왜 탐지하는가"** 를 실제 공격 요청과 ModSecurity 감사 로그로 함께 보여주는
패턴 라이브러리를 만드는 것이 최종 목표다.

## 산출물 형태

룰 단위로 다음 내용을 정리한다.

| 항목 | 설명 |
|------|------|
| 룰 설명 | rule id, 파일/라인, phase, paranoia level, 매칭 변수·연산자·변환 |
| 공격 예제 | 해당 룰을 트리거하는 HTTP 요청(payload) |
| 탐지 로그 | ModSecurity audit log / error log 의 실제 매칭 결과 |
| 비고 | 오탐(FP) 가능성, 우회 포인트, 관련 룰(CWE/CAPEC) |

## 디렉토리 구성 (예정)

```
crs-pattern-lab/
├── README.md
├── docs/
│   └── environment/          # 환경 구성 문서 (소스 빌드 / 패키지 설치)
├── modsecurity/              # ModSecurity directive / 설정 분석 문서
│   └── base-rules/           #   기본룰 분석
├── rules/                    # 룰별 분석 문서 (파일/룰 단위)
├── payloads/                 # 공격 예제 (HTTP 요청, 스크립트)
└── logs/
    └── local_test/           # 스크립트가 생성한 임시 테스트 로그 (검증/공격 테스트)
```

> 위 구조는 분석이 진행되면서 채워 나간다.

## 분석 문서

`modsecurity/` (실행 모델)

- [ModSecurity 실행 모델 (설정 vs 룰, phase)](modsecurity/execution-model.md)
  — directive/rule 적용·실행 시점, nginx 커넥터 훅, 로그가 남는 조건
- [CRS 점수와 Paranoia Level 연결](modsecurity/score-and-paranoia.md)
  — 룰 매칭 → 점수 누적(severity/변수) → PL 게이트 → 949 차단의 전체 연결

`modsecurity/base-rules/` (기본룰 분석)

- [modsecurity.conf Directive 분석](modsecurity/base-rules/modsecurity-conf.md)
  — 엔진/본문/응답/감사 로그/내장 룰 분석 (CRS Include 제외)
- [crs-setup.conf Directive 분석](modsecurity/base-rules/crs-setup-conf.md)
  — CRS 정책 변수/기본 동작/튜닝 옵션 분석

`rules/` (CRS 룰 파일별 분석 + 룰 id 검증 예제)

- [REQUEST-901-INITIALIZATION.conf](rules/REQUEST-901-INITIALIZATION/README.md)
  — **901은 공격을 막는 파일이 아니다.**
- [REQUEST-905-COMMON-EXCEPTIONS.conf](rules/REQUEST-905-COMMON-EXCEPTIONS/README.md)
  — **로컬(127.0.0.1)에서 오는 서버 자체 헬스체크 요청을, CRS가 오탐하지 않도록 잠시 면제해 주는 파일.**
- [REQUEST-911-METHOD-ENFORCEMENT.conf](rules/REQUEST-911-METHOD-ENFORCEMENT/README.md)
  — **"허용 목록(`tx.allowed_methods`)에 없는 HTTP 메서드로 요청하면, CRS가 403으로 막는다."**
- [REQUEST-913-SCANNER-DETECTION.conf](rules/REQUEST-913-SCANNER-DETECTION/README.md)
  — **요청의 `User-Agent` 가 알려진 보안 스캐너 목록(`scanners-user-agents.data`)에 있으면 403으로 차단한다.**
- [REQUEST-920-PROTOCOL-ENFORCEMENT.conf](rules/REQUEST-920-PROTOCOL-ENFORCEMENT/README.md)
  — **HTTP 규약을 어긴 요청(헤더/본문/인자/Content-Type 등)을 탐지해, 정책 위반이면 403으로 차단한다.**
- [REQUEST-921-PROTOCOL-ATTACK.conf](rules/REQUEST-921-PROTOCOL-ATTACK/README.md)
  — **HTTP 프로토콜을 악용한 공격 패턴을 탐지한다.**
- [REQUEST-922-MULTIPART-ATTACK.conf](rules/REQUEST-922-MULTIPART-ATTACK/README.md)
  — 멀티파트(form-data) 파싱을 악용한 공격(charset/transfer-encoding/헤더 조작)을 탐지한다.
- [REQUEST-930-APPLICATION-ATTACK-LFI.conf](rules/REQUEST-930-APPLICATION-ATTACK-LFI/README.md)
  — 로컬 파일 포함(LFI) 공격을 탐지한다.
- [REQUEST-931-APPLICATION-ATTACK-RFI.conf](rules/REQUEST-931-APPLICATION-ATTACK-RFI/README.md)
  — 원격 파일 포함(RFI) 공격을 탐지한다.
- [REQUEST-932-APPLICATION-ATTACK-RCE.conf](rules/REQUEST-932-APPLICATION-ATTACK-RCE/README.md)
  — 원격 명령 실행(RCE) 공격을 탐지한다.
- [REQUEST-933-APPLICATION-ATTACK-PHP.conf](rules/REQUEST-933-APPLICATION-ATTACK-PHP/README.md)
  — PHP 코드/함수 삽입 공격을 탐지한다.
- [REQUEST-934-APPLICATION-ATTACK-GENERIC.conf](rules/REQUEST-934-APPLICATION-ATTACK-GENERIC/README.md)
  — 여러 공격 유형에 걸친 제네릭(휴리스틱) 공격을 탐지한다.
- [REQUEST-941-APPLICATION-ATTACK-XSS.conf](rules/REQUEST-941-APPLICATION-ATTACK-XSS/README.md)
  — XSS(크로스사이트 스크립팅) 공격을 탐지한다.
- [REQUEST-942-APPLICATION-ATTACK-SQLI.conf](rules/REQUEST-942-APPLICATION-ATTACK-SQLI/README.md)
  — SQL 인젝션 공격을 탐지한다.
- [REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf](rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION/README.md)
  — 세션 고정(Session Fixation) 공격을 탐지한다.
- [REQUEST-944-APPLICATION-ATTACK-JAVA.conf](rules/REQUEST-944-APPLICATION-ATTACK-JAVA/README.md)
  — Java(LDAP/Log4Shell 등) 공격을 탐지한다.
- [REQUEST-949-BLOCKING-EVALUATION.conf](rules/REQUEST-949-BLOCKING-EVALUATION/README.md)
  — 요청(인바운드) 점수가 임계값을 넘으면 403으로 차단한다.
- [REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf](rules/REQUEST-999-COMMON-EXCEPTIONS-AFTER/README.md)
  — CRS 이후 공통 예외(사용자 추가용 템플릿, 기본은 비어 있음).
- [RESPONSE-950-DATA-LEAKAGES.conf](rules/RESPONSE-950-DATA-LEAKAGES/README.md)
  — 응답에서 데이터 유출(에러/소스 노출)을 탐지한다.
- [RESPONSE-951-DATA-LEAKAGES-SQL.conf](rules/RESPONSE-951-DATA-LEAKAGES-SQL/README.md)
  — 응답에서 SQL 에러/정보 유출을 탐지한다.
- [RESPONSE-952-DATA-LEAKAGES-JAVA.conf](rules/RESPONSE-952-DATA-LEAKAGES-JAVA/README.md)
  — 응답에서 Java 에러/스택트레이스 유출을 탐지한다.
- [RESPONSE-953-DATA-LEAKAGES-PHP.conf](rules/RESPONSE-953-DATA-LEAKAGES-PHP/README.md)
  — 응답에서 PHP 에러 유출을 탐지한다.
- [RESPONSE-954-DATA-LEAKAGES-IIS.conf](rules/RESPONSE-954-DATA-LEAKAGES-IIS/README.md)
  — 응답에서 IIS 에러 유출을 탐지한다.
- [RESPONSE-955-WEB-SHELLS.conf](rules/RESPONSE-955-WEB-SHELLS/README.md)
  — 응답에서 웹셸/백도어 흔적을 탐지한다.
- [RESPONSE-956-DATA-LEAKAGES-RUBY.conf](rules/RESPONSE-956-DATA-LEAKAGES-RUBY/README.md)
  — 응답에서 Ruby 에러 유출을 탐지한다.
- [RESPONSE-959-BLOCKING-EVALUATION.conf](rules/RESPONSE-959-BLOCKING-EVALUATION/README.md)
  — 아웃바운드 점수 임계 초과 시 응답을 차단한다.
- [RESPONSE-980-CORRELATION.conf](rules/RESPONSE-980-CORRELATION/README.md)
  — 요청/응답 단계의 어노말리 점수를 상관분석하고 통계를 남긴다.
- [RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf](rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS/README.md)
  — 응답 단계 CRS 이후 예외/차단동작 변경 템플릿(기본은 비어 있음).

## 환경 구성

검증 환경을 구성하는 방법은 `docs/environment/` 를 참고한다.

- [환경 구성 개요](docs/environment/README.md)
- [소스 코드 빌드](docs/environment/01-source-build.md)
- [패키지 설치](docs/environment/02-package-install.md)

## 참고 링크

- OWASP CRS: <https://github.com/coreruleset/coreruleset>
- CRS 문서: <https://coreruleset.org/docs/>
- ModSecurity v3: <https://github.com/owasp-modsecurity/ModSecurity>
- ModSecurity-nginx: <https://github.com/owasp-modsecurity/ModSecurity-nginx>
- ModSecurity Reference Manual: <https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)>

## 라이선스 / 주의

분석 대상인 CRS, ModSecurity 는 각 프로젝트의 라이선스를 따른다.
이 저장소의 공격 예제는 **분석/교육용**이며, 허가된 시스템에 대해서만 사용한다.
