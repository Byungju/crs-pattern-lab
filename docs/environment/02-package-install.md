# 패키지 설치로 환경 구성

소스를 빌드하지 않고 배포판 패키지 또는 컨테이너 이미지로 환경을 구성하는 방법이다.
빠르지만 배포판이 제공하는 버전으로 고정된다.

> Ubuntu 24.04(noble) 기준. 패키지 버전은 저장소 시점에 따라 달라질 수 있다.

## 방법 A. Ubuntu 패키지 (nginx + libmodsecurity + CRS)

### 설치되는 버전 (예시)

| 패키지 | 버전 |
|--------|------|
| `nginx` | 1.24.0 |
| `libnginx-mod-http-modsecurity` | 1.0.3 (nginx 동적 모듈) |
| `libmodsecurity3t64` | 3.0.12 |
| `modsecurity-crs` | 3.3.5 (**CRS 3.x**) |

> `libmodsecurity3` 대신 `libmodsecurity3t64` 라는 이름을 쓴다(time_t 전환).
> 배포판 CRS 는 **3.x** 라서 소스 빌드의 4.x 와 룰 구성이 다르다
> (예: `REQUEST-912-DOS-PROTECTION.conf`, `REQUEST-910-IP-REPUTATION.conf`,
> `REQUEST-903.900x-<APP>-EXCLUSION-RULES.conf` 등).

### 1) 설치

```bash
sudo apt-get update
sudo apt-get install -y \
  nginx \
  libnginx-mod-http-modsecurity \
  libmodsecurity3t64 \
  modsecurity-crs
```

`libnginx-mod-http-modsecurity` 는 다음 패키지를 함께 끌어온다.
`libnginx-mod-http-ndk`, `libmodsecurity-dev`, `libmodsecurity3t64`.

### 2) 동적 모듈 로드

패키지가 `/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf` 심볼릭 링크를
자동 생성하며, 내용은 다음과 같다.

```
load_module modules/ngx_http_modsecurity_module.so;
```

nginx 는 `/etc/nginx/modules-enabled/*.conf` 를 include 하므로 nginx.conf 에서
`load_module` 을 직접 추가하지 않아도 된다. (없으면 수동 추가)

### 3) 주요 파일 위치

| 용도 | 경로 |
|------|------|
| nginx 모듈 | `/usr/lib/nginx/modules/ngx_http_modsecurity_module.so` |
| ModSecurity 엔진 설정 | `/etc/nginx/modsecurity.conf` |
| include 진입점 | `/etc/nginx/modsecurity_includes.conf` |
| unicode map | `/etc/nginx/unicode.mapping` |
| CRS 활성화 로더 | `/usr/share/modsecurity-crs/owasp-crs.load` |
| CRS 룰 | `/usr/share/modsecurity-crs/rules/*.conf` |
| CRS 사용자 설정/예외 | `/etc/modsecurity/crs/crs-setup.conf`, `REQUEST-900-*.conf`, `RESPONSE-999-*.conf` |

### 4) 엔진 켜기

`/etc/nginx/modsecurity.conf` 의 엔진 모드를 변경한다.

```
SecRuleEngine On
# 초기 도입 시에는 DetectionOnly 로 시작해도 된다.
```

### 5) CRS 활성화

`/etc/nginx/modsecurity_includes.conf` 의 CRS include 주석을 해제한다.

```
include modsecurity.conf
include /usr/share/modsecurity-crs/owasp-crs.load
```

`owasp-crs.load` 는 내부적으로 아래를 include 한다.

```
Include /etc/modsecurity/crs/crs-setup.conf
IncludeOptional /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /usr/share/modsecurity-crs/rules/*.conf
IncludeOptional /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
```

### 6) nginx server 블록에 적용

```nginx
server {
    listen 80;
    server_name localhost;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity_includes.conf;

    location / {
        root /var/www/html;
        index index.html;
    }
}
```

### 7) 반영 및 검증

```bash
sudo nginx -t
sudo systemctl restart nginx

curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1/?id=1%27%20OR%20%271%27%3D%271"   # 403 기대
sudo tail -f /var/log/nginx/error.log
```

## 방법 B. Apache (참고)

CRS 는 Apache + ModSecurity v2 조합으로도 검증할 수 있다.

```bash
sudo apt-get install -y apache2 libapache2-mod-security2 modsecurity-crs
sudo a2enmod security2
sudo systemctl restart apache2
```

- 엔진 설정: `/etc/modsecurity/modsecurity.conf` (`SecRuleEngine On`)
- CRS 로더: `/etc/modsecurity/crs/` + `/usr/share/modsecurity-crs/`
- 룰 파일을 `Include` 하여 사용한다.

## 방법 C. Docker (owasp/modsecurity-crs)

가장 빠른 방법. WAF 컨테이너가 백엔드로 프록시하는 구조다.

```bash
docker run --rm -p 8088:8080 \
  -e BACKEND="http://<backend-host>:<port>" \
  -e PORT=8080 \
  -e MODSEC_RULE_ENGINE=On \
  -e PARANOIA=1 \
  -e BLOCKING_PARANOIA=1 \
  -e TZ=Asia/Seoul \
  owasp/modsecurity-crs:nginx
```

- 이미지 태그: `owasp/modsecurity-crs:nginx`, `owasp/modsecurity-crs:apache`
- 주요 환경변수: `BACKEND`, `PORT`, `MODSEC_RULE_ENGINE`, `PARANOIA`,
  `BLOCKING_PARANOIA`, `DETECTION_PARANOIA`, `MODSEC_AUDIT_LOG*`, `TZ`
- 컨테이너 내부 CRS 버전은 이미지 태그에 따른다(최신 태그는 4.x).

## 방식별 요약

| 항목 | 소스 빌드 | apt 패키지 | Docker |
|------|-----------|-----------|--------|
| 난이도 | 높음 | 낮음 | 매우 낮음 |
| 버전 선택 | 자유 | 배포판 고정 | 이미지 태그 |
| CRS 버전 | 4.x 최신 | 3.x | 이미지 의존 |
| 엔진 기능 선택 | 자유 | 고정 | 이미지 의존 |
| 분석용 커스터마이즈 | 쉬움 | 보통 | 어려움 |

룰/엔진을 세밀하게 분석하려면 **소스 빌드**([01-source-build.md](01-source-build.md))를,
동작 확인만 빠르게 하려면 패키지/도커를 권장한다.
