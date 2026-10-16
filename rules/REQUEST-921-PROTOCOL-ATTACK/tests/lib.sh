#!/usr/bin/env bash
# lib.sh - REQUEST-921-PROTOCOL-ATTACK 검증 하네스 공용 라이브러리
#
# 921 은 HTTP 프로토콜 공격(Header Injection, Response Splitting, Smuggling,
# Parameter Pollution, LDAP Injection 등)을 탐지한다.
#
# PL2~4 룰이 많아, 테스트는 detection/blocking PL=4 로 설정해 모든 PL 을 실행/차단한다.

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="${LAB:-/home/ubuntu/web_security}"
NGINX_PREFIX="$LAB/install/nginx"
NGINX="$NGINX_PREFIX/sbin/nginx"
CONF_DIR="$NGINX_PREFIX/conf"
CRS_DIR="$CONF_DIR/crs"

PROJECT_ROOT="$(cd "$HARNESS_DIR/../../.." && pwd)"
LOG_SUBDIR="REQUEST-921-PROTOCOL-ATTACK"
TEST_LOG_DIR="$PROJECT_ROOT/logs/local_test/$LOG_SUBDIR"
mkdir -p "$TEST_LOG_DIR"

PORT="${PORT:-8104}"
ERRLOG="$TEST_LOG_DIR/nginx-error.log"
AUDITLOG="$TEST_LOG_DIR/nginx-audit.log"

PASS=0
FAIL=0
SKIP=0
CURRENT_LOG="${CURRENT_LOG:-}"

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_rst=$'\033[0m'

_log() { [ -n "$CURRENT_LOG" ] && printf '%s\n' "$*" >> "$CURRENT_LOG"; return 0; }
pass() { PASS=$((PASS+1)); printf '  %sPASS%s %s\n' "$c_grn" "$c_rst" "$*"; _log "PASS $*"; }
fail() { FAIL=$((FAIL+1)); printf '  %sFAIL%s %s\n' "$c_red" "$c_rst" "$*"; _log "FAIL $*"; }
skip() { SKIP=$((SKIP+1)); printf '  %sSKIP%s %s\n' "$c_yel" "$c_rst" "$*"; _log "SKIP $*"; }
info() { printf '       %s\n' "$*"; _log "     $*"; }

gen_conf() {
    cat > "$CONF_DIR/crs-t921-modsec.conf" <<EOF
SecRuleEngine On
SecRequestBodyAccess On
SecTmpDir /tmp/
SecDataDir /tmp/
SecUnicodeMapFile $CONF_DIR/unicode.mapping 20127
SecAuditEngine On
SecAuditLog $AUDITLOG
SecAuditLogType Serial
SecAuditLogParts ABIJDEFHZ
Include $CRS_DIR/crs-setup.conf
SecAction "id:9900921,phase:1,pass,nolog,setvar:tx.detection_paranoia_level=4,setvar:tx.blocking_paranoia_level=4"
Include $CRS_DIR/rules/*.conf
EOF
    cat > "$CONF_DIR/crs-t921-nginx.conf" <<EOF
worker_processes 1;
error_log $ERRLOG info;
pid $TEST_LOG_DIR/nginx.pid;
events { worker_connections 64; }
http {
    include mime.types;
    default_type application/octet-stream;
    modsecurity on;
    access_log $TEST_LOG_DIR/nginx-access.log;
    modsecurity_rules_file $CONF_DIR/crs-t921-modsec.conf;
    server {
        listen 127.0.0.1:$PORT;
        location / { root html; index index.html; }
    }
}
EOF
}

start_nginx() {
    stop_nginx
    "$NGINX" -p "$NGINX_PREFIX" -c "$CONF_DIR/crs-t921-nginx.conf" 2>/dev/null
    local i
    for i in $(seq 1 30); do
        [ "$(curl -s -o /dev/null -m 2 -w '%{http_code}' "http://127.0.0.1:$PORT/")" != "000" ] && break
        sleep 0.1
    done
    sleep 0.2
}
stop_nginx() {
    "$NGINX" -p "$NGINX_PREFIX" -c "$CONF_DIR/crs-t921-nginx.conf" -s stop 2>/dev/null || true
    sleep 0.2
}

reset_logs() { : > "$ERRLOG"; : > "$AUDITLOG"; }

curl_code() { reset_logs; curl -s -o /dev/null -m 5 -w '%{http_code}' -H 'Host: localhost' "$@" 2>/dev/null; sleep 0.2; }

count_id() { grep -ac "id \"$1\"" "$ERRLOG" 2>/dev/null; }
last_id()  { grep -a "id \"$1\"" "$ERRLOG" 2>/dev/null | tail -1; }

assert_eq() { # desc expected actual
    _log "  (actual=$3 expected=$2)"
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (기대 '$2' / 실제 '$3')"; fi
}
assert_fired() { # id desc
    local n; n="$(count_id "$1")"
    [ -n "$(last_id "$1")" ] && printf 'LOG %s\n' "$(last_id "$1")" >> "$CURRENT_LOG"
    if [ "$n" -ge 1 ]; then pass "$2 (id $1 매칭)"; else fail "$2 (id $1 미발견)"; fi
}

cleanup_artifacts() { rm -f "$CONF_DIR"/crs-t921-*.conf; return 0; }
