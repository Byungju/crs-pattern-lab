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

`modsecurity/base-rules/` (기본룰 분석)

- [modsecurity.conf Directive 분석](modsecurity/base-rules/modsecurity-conf.md)
  — 엔진/본문/응답/감사 로그/내장 룰 분석 (CRS Include 제외)
- [crs-setup.conf Directive 분석](modsecurity/base-rules/crs-setup-conf.md)
  — CRS 정책 변수/기본 동작/튜닝 옵션 분석

`rules/` (CRS 룰 파일별 분석 + 룰 id 검증 예제)

- [REQUEST-901-INITIALIZATION.conf](rules/REQUEST-901-INITIALIZATION/README.md)
  — 초기화 룰 분석 + 룰 id별 검증 스크립트/로그 (`tests/`)
- [REQUEST-905-COMMON-EXCEPTIONS.conf](rules/REQUEST-905-COMMON-EXCEPTIONS/README.md)
  — 예외(화이트리스트) 룰 분석 + 검증 (`905100` 미발동 발견, `905110` 정상)

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
