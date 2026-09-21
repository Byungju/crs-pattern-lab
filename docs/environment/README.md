# 환경 구성 개요

이 디렉토리는 crs-pattern-lab 의 검증 환경(nginx + libmodsecurity + CRS)을
구성하는 방법을 정리한다. 동일한 목적을 두 가지 방식으로 달성할 수 있다.

| 방식 | 문서 | 엔진 버전 | CRS 버전 | 특징 |
|------|------|-----------|----------|------|
| 소스 코드 빌드 | [01-source-build.md](01-source-build.md) | 최신 (Git master) | 최신 (Git, 4.x) | 버전·기능·모듈을 원하는 대로 선택. 빌드 시간 소요 |
| 패키지 설치 | [02-package-install.md](02-package-install.md) | 배포판 버전 | 배포판 버전 | 빠르고 간단. 배포판이 제공하는 버전으로 고정 |

## 어떤 방식을 쓸까

- **최신 룰/엔진을 분석**하고 특정 버전을 고정하고 싶다 → **소스 빌드**
  (이 랩의 기본 전제: CRS 4.x + libmodsecurity 3.x 최신)
- **빠르게 동작만 확인**하고 배포판 버전으로 충분하다 → **패키지 설치**
  (Ubuntu 24.04 기준 CRS 3.3.5, libmodsecurity 3.0.12)

두 방식 모두 최종적으로 아래 3요소를 갖춘다.

```
nginx  ──(ModSecurity-nginx 커넥터)──▶  libmodsecurity  ──▶  OWASP CRS rules
```

## 공통 개념: 설정 파일 3계층

방식과 무관하게 설정은 크게 세 층으로 나뉜다.

1. **nginx 측 설정** (`nginx.conf`)
   - `modsecurity on;`
   - `modsecurity_rules_file <modsecurity 설정 파일 경로>;`
2. **ModSecurity 엔진 설정** (`modsecurity.conf`)
   - `SecRuleEngine On|DetectionOnly`
   - 요청 본문 파싱, 감사 로그, XML/JSON 파서 트리거 등 엔진 레벨 룰
3. **CRS 설정/룰** (`crs-setup.conf` + `rules/*.conf`)
   - 이상 점수(anomaly score), 허용 메서드/콘텐츠 타입, paranoia level 등
   - 실제 공격 탐지 룰

## 검증 방법 (공통)

```bash
# 정상 요청
curl -i "http://127.0.0.1:8088/"

# SQLi (CRS 942100 등 탐지, 403 기대)
curl -i "http://127.0.0.1:8088/?id=1%27%20OR%20%271%27%3D%271"

# XSS (CRS 941100/941110 등 탐지, 403 기대)
curl -i "http://127.0.0.1:8088/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

탐지 확인은 감사 로그에서 rule id 를 검색한다.

```bash
grep -o '\[id "[0-9]*"\]' /path/to/modsecurity_audit.log | sort | uniq -c
```
