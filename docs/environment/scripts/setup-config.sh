#!/usr/bin/env bash
#
# setup-config.sh
#
# 빌드된 install/nginx 에 ModSecurity + OWASP CRS 설정 파일을 구성한다.
#
#   - install/nginx/conf/modsecurity.conf : ModSecurity 엔진 설정 + CRS include
#   - install/nginx/conf/crs/             : CRS (crs-setup.conf, rules, plugins)
#   - install/nginx/conf/nginx.conf       : modsecurity on + rules_file 지정
#
# 사용법:
#   ./setup-config.sh            # 기존 설정 덮어쓰기
#   ./setup-config.sh --no-nginx # nginx.conf 는 건드리지 않음
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$ROOT_DIR/install"
NGINX_PREFIX="$INSTALL_DIR/nginx"
CONF_DIR="$NGINX_PREFIX/conf"
CRS_SRC="$ROOT_DIR/coreruleset"
CRS_DST="$CONF_DIR/crs"
MODSEC_RECOMMENDED="$ROOT_DIR/src/ModSecurity/modsecurity.conf-recommended"

WRITE_NGINX_CONF=1
HTTP_PORT="${HTTP_PORT:-8088}"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --no-nginx) WRITE_NGINX_CONF=0 ;;
        -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "알 수 없는 옵션: $1" ;;
    esac
    shift
done

[ -x "$NGINX_PREFIX/sbin/nginx" ] || die "nginx 가 없습니다. 먼저 ./build.sh 실행"
[ -f "$MODSEC_RECOMMENDED" ] || die "modsecurity.conf-recommended 없음"
[ -d "$CRS_SRC/rules" ] || die "coreruleset 소스 없음"

# 1. CRS 파일 복사 (+ .example 활성화)
log "CRS 설치: $CRS_DST"
rm -rf "$CRS_DST"
mkdir -p "$CRS_DST"
cp -a "$CRS_SRC/rules" "$CRS_DST/"
cp -a "$CRS_SRC/plugins" "$CRS_DST/"
cp -a "$CRS_SRC/crs-setup.conf.example" "$CRS_DST/crs-setup.conf"
find "$CRS_DST" -name '*.example' -print0 | while IFS= read -r -d '' f; do
    mv "$f" "${f%.example}"
done

# 2. modsecurity.conf 생성 (권장 설정 + 엔진 On + 감사로그 + CRS include)
log "ModSecurity 설정 생성: $CONF_DIR/modsecurity.conf"
cp "$ROOT_DIR/src/ModSecurity/unicode.mapping" "$CONF_DIR/unicode.mapping"
sed 's/^SecRuleEngine DetectionOnly/SecRuleEngine On/' \
    "$MODSEC_RECOMMENDED" > "$CONF_DIR/modsecurity.conf"

cat >> "$CONF_DIR/modsecurity.conf" <<EOF

# ---------------------------------------------------------------------------
# Local overrides (setup-config.sh)
# ---------------------------------------------------------------------------
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog "$NGINX_PREFIX/logs/modsecurity_audit.log"
SecDebugLog "$NGINX_PREFIX/logs/modsecurity_debug.log"
SecDebugLogLevel 0

# --- OWASP CRS ---
Include $CRS_DST/crs-setup.conf
Include $CRS_DST/plugins/*-config.conf
Include $CRS_DST/plugins/*-before.conf
Include $CRS_DST/rules/*.conf
Include $CRS_DST/plugins/*-after.conf
EOF

# 3. nginx.conf 생성 (기본 설정 + modsecurity)
if [ "$WRITE_NGINX_CONF" -eq 1 ]; then
    log "nginx 설정 생성: $CONF_DIR/nginx.conf"
    [ -f "$CONF_DIR/nginx.conf" ] && cp "$CONF_DIR/nginx.conf" "$CONF_DIR/nginx.conf.bak"
    cat > "$CONF_DIR/nginx.conf" <<EOF
worker_processes  1;
error_log  logs/error.log  warn;
pid        logs/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent"';

    access_log  logs/access.log  main;
    sendfile        on;
    keepalive_timeout  65;

    # --- ModSecurity ---
    modsecurity on;
    modsecurity_rules_file  $CONF_DIR/modsecurity.conf;

    server {
        listen       $HTTP_PORT;
        server_name  localhost;

        location / {
            root   html;
            index  index.html index.htm;
        }

        location = /50x.html {
            root   html;
        }
    }
}
EOF
fi

log "완료"
cat <<EOF

구성 요약
  modsecurity.conf : $CONF_DIR/modsecurity.conf
  CRS              : $CRS_DST
  nginx.conf       : $CONF_DIR/nginx.conf
  listen port      : $HTTP_PORT

검증
  $NGINX_PREFIX/sbin/nginx -t
  $NGINX_PREFIX/sbin/nginx

테스트 (CRS 차단 확인)
  curl -i "http://127.0.0.1:$HTTP_PORT/?id=1%27%20OR%20%271%27%3D%271"
EOF
