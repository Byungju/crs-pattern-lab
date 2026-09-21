# 소스 코드 빌드로 환경 구성

nginx + libmodsecurity(v3) + ModSecurity-nginx 커넥터 + OWASP CRS 를
소스에서 직접 빌드하는 방법이다. 원하는 버전/기능을 고정할 수 있다.

## 검증한 버전

| 구성요소 | 버전 | 소스 |
|----------|------|------|
| nginx | 1.31.7 (master) | <https://github.com/nginx/nginx> |
| libmodsecurity | 3.0.16 (v3/master) | <https://github.com/owasp-modsecurity/ModSecurity> |
| ModSecurity-nginx | 1.0.4 | <https://github.com/owasp-modsecurity/ModSecurity-nginx> |
| OWASP CRS | 4.30.0-dev | <https://github.com/coreruleset/coreruleset> |

> 주의: 이 nginx 소스는 top-level `configure` 없이 **`auto/configure`** 를 사용한다.

## 0. 디렉토리 예시

```bash
export LAB=/home/ubuntu/web_security
mkdir -p "$LAB/src" "$LAB/install"
```

## 1. 의존성 설치 (Ubuntu 24.04)

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential autoconf automake libtool libtool-bin pkg-config m4 \
  zlib1g-dev libssl-dev libpcre2-dev libxml2-dev libyajl-dev \
  libcurl4-openssl-dev liblua5.4-dev liblmdb-dev \
  git curl
```

## 2. 소스 준비

```bash
cd "$LAB/src"

# nginx / ModSecurity / 커넥터
git clone https://github.com/nginx/nginx.git
git clone https://github.com/owasp-modsecurity/ModSecurity.git
git clone https://github.com/owasp-modsecurity/ModSecurity-nginx.git

# CRS
cd "$LAB"
git clone https://github.com/coreruleset/coreruleset.git

# ModSecurity 필수 submodule (configure 가 존재를 검사)
cd "$LAB/src/ModSecurity"
git submodule update --init --recursive others/libinjection others/mbedtls
```

## 3. libmodsecurity 빌드

CRS 분석에 필요한 기능을 모두 켠다.

```bash
cd "$LAB/src/ModSecurity"
./build.sh            # autotools configure 생성
./configure \
  --prefix="$LAB/install/modsecurity" \
  --with-pcre2 \
  --with-yajl \
  --with-libxml \
  --with-lua \
  --with-curl \
  --with-lmdb \
  --disable-examples
make -j"$(nproc)"
make install
```

| 옵션 | 용도 |
|------|------|
| `--with-pcre2` | 룰 정규식 엔진 |
| `--with-lmdb` | 영구 컬렉션(IP/세션 저장) |
| `--with-curl` | SSRF/외부 리소스 |
| `--with-yajl` | JSON 파싱 |
| `--with-libxml` | XML 파싱 |
| `--with-lua` | Lua 스크립트 룰 |

## 4. nginx + 커넥터 빌드

```bash
cd "$LAB/src/nginx"

MODSECURITY_INC="$LAB/install/modsecurity/include" \
MODSECURITY_LIB="$LAB/install/modsecurity/lib" \
./auto/configure \
  --prefix="$LAB/install/nginx" \
  --with-pcre \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_realip_module \
  --with-http_stub_status_module \
  --with-http_gzip_static_module \
  --with-cc-opt="-I$LAB/install/modsecurity/include" \
  --with-ld-opt="-L$LAB/install/modsecurity/lib -Wl,-rpath,$LAB/install/modsecurity/lib" \
  --add-module="$LAB/src/ModSecurity-nginx"

make -j"$(nproc)"
make install
```

- 커넥터는 nginx 필터 모듈로 정적 링크된다.
- `MODSECURITY_INC` / `MODSECURITY_LIB` 로 libmodsecurity 위치를 알려준다.
- `-Wl,-rpath` 로 실행 시 `libmodsecurity.so` 를 찾게 한다.

## 5. CRS 배치

```bash
CRS="$LAB/install/nginx/conf/crs"
mkdir -p "$CRS"
cp -a "$LAB/coreruleset/rules" "$CRS/"
cp -a "$LAB/coreruleset/plugins" "$CRS/"
cp "$LAB/coreruleset/crs-setup.conf.example" "$CRS/crs-setup.conf"

# .example 활성화
find "$CRS" -name '*.example' -exec sh -c 'mv "$1" "${1%.example}"' _ {} \;

# unicode map (modsecurity.conf 의 SecUnicodeMapFile 이 참조)
cp "$LAB/src/ModSecurity/unicode.mapping" "$LAB/install/nginx/conf/unicode.mapping"
```

## 6. ModSecurity 엔진 설정

`src/ModSecurity/modsecurity.conf-recommended` 를 기반으로
엔진을 켜고 감사 로그/CRS include 를 추가한다.

```bash
CONF="$LAB/install/nginx/conf"
sed 's/^SecRuleEngine DetectionOnly/SecRuleEngine On/' \
    "$LAB/src/ModSecurity/modsecurity.conf-recommended" > "$CONF/modsecurity.conf"
```

`modsecurity.conf` 끝에 추가:

```
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog  /home/ubuntu/web_security/install/nginx/logs/modsecurity_audit.log
SecDebugLog  /home/ubuntu/web_security/install/nginx/logs/modsecurity_debug.log
SecDebugLogLevel 0

Include <CRS>/crs-setup.conf
Include <CRS>/plugins/*-config.conf
Include <CRS>/plugins/*-before.conf
Include <CRS>/rules/*.conf
Include <CRS>/plugins/*-after.conf
```

## 7. nginx 설정

`install/nginx/conf/nginx.conf` 의 `http {}` 안에 추가:

```nginx
http {
    modsecurity on;
    modsecurity_rules_file /home/ubuntu/web_security/install/nginx/conf/modsecurity.conf;

    server {
        listen 8088;
        server_name localhost;
        location / { root html; index index.html; }
    }
}
```

## 8. 검증

```bash
NGX="$LAB/install/nginx/sbin/nginx"
$NGX -t -p "$LAB/install/nginx"          # 문법 검사
$NGX -p "$LAB/install/nginx"             # 기동

curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8088/"                                  # 200
curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8088/?id=1%27%20OR%20%271%27%3D%271"    # 403
curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8088/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" # 403

$NGX -p "$LAB/install/nginx" -s stop
```

기동 시 error log 에 아래처럼 로드된 룰 개수가 찍히면 정상이다.

```
ModSecurity-nginx v1.0.4 (rules loaded inline/local/remote: 0/847/0)
```

## 자동화 스크립트

이 랩에서는 위 과정을 스크립트로 자동화해 두었다.

- `build.sh` : 의존성 설치 + libmodsecurity/nginx 빌드 + `install/` 설치
  - `--no-deps`, `--only-modsec`, `--only-nginx`, `--clean`, `-j N`
- `setup-config.sh` : CRS 배치 + `modsecurity.conf`/`nginx.conf` 생성

```bash
./build.sh              # 전체 빌드
./setup-config.sh       # 설정 구성 (HTTP_PORT 환경변수로 포트 변경)
```
