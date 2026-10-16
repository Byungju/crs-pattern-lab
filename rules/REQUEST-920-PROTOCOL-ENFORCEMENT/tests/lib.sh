#!/usr/bin/env bash
# lib.sh - REQUEST-920-PROTOCOL-ENFORCEMENT 검증 하네스 공용 라이브러리
#
# 920 은 HTTP 프로토콜 위반을 탐지하는 파일이다.
# 주의: nginx 가 ModSecurity(CRS) 도달 전에 400/405 로 먼저 막는 요청이 많아,
#       모든 룰을 이 환경에서 트리거할 수는 없다(도달 가능한 룰만 검증).

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="${LAB:-/home/ubuntu/web_security}"
NGINX_PREFIX="$LAB/install/nginx"
NGINX="$NGINX_PREFIX/sbin/nginx"
CONF_DIR="$NGINX_PREFIX/conf"
CRS_DIR="$CONF_DIR/crs"

PROJECT_ROOT="$(cd "$HARNESS_DIR/../../.." && pwd)"
LOG_SUBDIR="REQUEST-920-PROTOCOL-ENFORCEMENT"
TEST_LOG_DIR="$PROJECT_ROOT/logs/local_test/$LOG_SUBDIR"
mkdir -p "$TEST_LOG_DIR"

PORT="${PORT:-8103}"
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
    cat > "$CONF_DIR/crs-t920-modsec.conf" <<EOF
Include $CONF_DIR/modsecurity.conf
SecAuditEngine On
SecAuditLog $AUDITLOG
SecAuditLogType Serial
SecAuditLogParts ABIJDEFHZ
EOF
    cat > "$CONF_DIR/crs-t920-nginx.conf" <<EOF
worker_processes 1;
error_log $ERRLOG info;
pid $TEST_LOG_DIR/nginx.pid;
events { worker_connections 64; }
http {
    include mime.types;
    default_type application/octet-stream;
    modsecurity on;
    access_log $TEST_LOG_DIR/nginx-access.log;
    modsecurity_rules_file $CONF_DIR/crs-t920-modsec.conf;
    server {
        listen 127.0.0.1:$PORT;
        location / { root html; index index.html; }
    }
}
EOF
}

start_nginx() {
    stop_nginx
    "$NGINX" -p "$NGINX_PREFIX" -c "$CONF_DIR/crs-t920-nginx.conf" 2>/dev/null
    local i
    for i in $(seq 1 30); do
        [ "$(curl -s -o /dev/null -m 2 -w '%{http_code}' "http://127.0.0.1:$PORT/")" != "000" ] && break
        sleep 0.1
    done
    sleep 0.2
}
stop_nginx() {
    "$NGINX" -p "$NGINX_PREFIX" -c "$CONF_DIR/crs-t920-nginx.conf" -s stop 2>/dev/null || true
    sleep 0.2
}

reset_logs() { : > "$ERRLOG"; : > "$AUDITLOG"; }


# multipart POST: $1 = "ContentType|body(\r\n escapes)" (Content-Length 자동 계산)
mp_code() {
    reset_logs
    python3 - "$1" "$PORT" <<'PYEOF' 2>/dev/null
import sys, socket, re
spec=sys.argv[1]; port=int(sys.argv[2])
ct, body = spec.split("|", 1)
body = body.encode().decode("unicode_escape").encode("latin-1")
req=(f"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: {ct}\r\n"
     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()+body
try:
    s=socket.create_connection(("127.0.0.1",port),timeout=5); s.sendall(req)
    data=b""
    while True:
        b=s.recv(4096)
        if not b: break
        data+=b
    s.close()
    m=re.search(rb"HTTP/1\.[01] (\d{3})", data)
    print(m.group(1).decode() if m else "000")
except Exception:
    print("000")
PYEOF
    sleep 0.2
}

# 표준 curl 요청 (로그 초기화 후)
curl_code() { reset_logs; curl -s -o /dev/null -m 5 -w '%{http_code}' "$@" 2>/dev/null; sleep 0.2; }

# raw HTTP 요청 (nc). $1 = printf %b 형식 문자열
raw_code() {
    reset_logs
    local out
    out="$(printf '%b' "$1" | nc -w2 127.0.0.1 "$PORT" 2>/dev/null | head -1)"
    sleep 0.2
    printf '%s' "$out" | grep -oE '[0-9]{3}' | head -1
}

count_id()    { grep -ac "id \"$1\"" "$ERRLOG" 2>/dev/null; }
last_id()     { grep -a "id \"$1\"" "$ERRLOG" 2>/dev/null | tail -1; }
audit_count() { grep -acE '^---[A-Za-z0-9]+---A--' "$AUDITLOG" 2>/dev/null; }

assert_eq() { # desc expected actual
    _log "  (actual=$3 expected=$2)"
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (기대 '$2' / 실제 '$3')"; fi
}

# 룰이 매칭되었는지 (id 로그 >= 1)
assert_fired() { # id desc
    local n; n="$(count_id "$1")"
    [ -n "$(last_id "$1")" ] && printf 'LOG %s\n' "$(last_id "$1")" >> "$CURRENT_LOG"
    if [ "$n" -ge 1 ]; then pass "$2 (id $1 매칭)"; else fail "$2 (id $1 미발견)"; fi
}

cleanup_artifacts() { rm -f "$CONF_DIR"/crs-t920-*.conf; return 0; }
