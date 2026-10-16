#!/usr/bin/env bash
# lib.sh - CRS 룰 파일 검증 하네스 공용 라이브러리 (범용)
#
# 같은 디렉토리의 harness.env 에서 설정을 읽는다.
#   CONF_NAME=REQUEST-922-MULTIPART-ATTACK.conf
#   LOG_SUBDIR=REQUEST-922-MULTIPART-ATTACK
#   PORT=8106
#   MODEL=pl4        # pl4 = detection/blocking PL=4, main = 기본(PL1) modsecurity.conf
#
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.env
source "$HARNESS_DIR/harness.env"

LAB="${LAB:-/home/ubuntu/web_security}"
NGINX_PREFIX="$LAB/install/nginx"
NGINX="$NGINX_PREFIX/sbin/nginx"
CONF_DIR="$NGINX_PREFIX/conf"
CRS_DIR="$CONF_DIR/crs"

PROJECT_ROOT="$(cd "$HARNESS_DIR/../../.." && pwd)"
TEST_LOG_DIR="$PROJECT_ROOT/logs/local_test/$LOG_SUBDIR"
mkdir -p "$TEST_LOG_DIR"

ERRLOG="$TEST_LOG_DIR/nginx-error.log"
AUDITLOG="$TEST_LOG_DIR/nginx-audit.log"

PASS=0; FAIL=0; SKIP=0
CURRENT_LOG="${CURRENT_LOG:-}"
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_rst=$'\033[0m'

_log() { [ -n "$CURRENT_LOG" ] && printf '%s\n' "$*" >> "$CURRENT_LOG"; return 0; }
pass() { PASS=$((PASS+1)); printf '  %sPASS%s %s\n' "$c_grn" "$c_rst" "$*"; _log "PASS $*"; }
fail() { FAIL=$((FAIL+1)); printf '  %sFAIL%s %s\n' "$c_red" "$c_rst" "$*"; _log "FAIL $*"; }
skip() { SKIP=$((SKIP+1)); printf '  %sSKIP%s %s\n' "$c_yel" "$c_rst" "$*"; _log "SKIP $*"; }
info() { printf '       %s\n' "$*"; _log "     $*"; }

gen_conf() {
    if [ "${MODEL:-main}" = "pl4" ]; then
        cat > "$CONF_DIR/crs-t9-modsec.conf" <<EOF
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
SecAction "id:9900900,phase:1,pass,nolog,setvar:tx.detection_paranoia_level=4,setvar:tx.blocking_paranoia_level=4"
Include $CRS_DIR/rules/*.conf
EOF
    else
        cat > "$CONF_DIR/crs-t9-modsec.conf" <<EOF
Include $CONF_DIR/modsecurity.conf
SecAuditEngine On
SecAuditLog $AUDITLOG
SecAuditLogType Serial
SecAuditLogParts ABIJDEFHZ
EOF
    fi
    cat > "$CONF_DIR/crs-t9-nginx.conf" <<EOF
worker_processes 1;
error_log $ERRLOG info;
pid $TEST_LOG_DIR/nginx.pid;
events { worker_connections 64; }
http {
    include mime.types;
    default_type application/octet-stream;
    modsecurity on;
    access_log $TEST_LOG_DIR/nginx-access.log;
    modsecurity_rules_file $CONF_DIR/crs-t9-modsec.conf;
    server {
        listen 127.0.0.1:$PORT;
        location / { root html; index index.html; }
    }
}
EOF
}

start_nginx() {
    stop_nginx
    "$NGINX" -p "$NGINX_PREFIX" -c "$CONF_DIR/crs-t9-nginx.conf" 2>/dev/null
    local i
    for i in $(seq 1 30); do
        [ "$(curl -s -o /dev/null -m 2 -w '%{http_code}' "http://127.0.0.1:$PORT/")" != "000" ] && break
        sleep 0.1
    done
    sleep 0.2
}
stop_nginx() {
    "$NGINX" -p "$NGINX_PREFIX" -c "$CONF_DIR/crs-t9-nginx.conf" -s stop 2>/dev/null || true
    sleep 0.2
}

reset_logs() { : > "$ERRLOG"; : > "$AUDITLOG"; }

# curl 요청: 로그 초기화 후 HTTP 코드 반환. 인자는 curl 에 그대로 전달.
curl_code() { reset_logs; curl -s -o /dev/null -m 5 -w '%{http_code}' -H 'Host: localhost' "$@" 2>/dev/null; sleep 0.2; }
# raw HTTP 요청: $1 = printf %b 형식 문자열
raw_code() { reset_logs; printf '%b' "$1" | nc -w2 127.0.0.1 "$PORT" 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1; sleep 0.2; }
# multipart POST: $1 = "ContentType|body(\\r\\n escapes)" (Content-Length 자동 계산)
mp_code() {
    reset_logs
    python3 - "$1" "$PORT" <<'PY' 2>/dev/null
import sys, socket, re
spec=sys.argv[1]; port=int(sys.argv[2])
ct, body = spec.split("|", 1)
body = body.encode().decode("unicode_escape").encode("latin-1")
req=(f"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: {ct}\r\n"
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
PY
    sleep 0.2
}
# 응답 본문까지 필요한 경우(raw): $1 = printf %b 형식
raw_body() { reset_logs; printf '%b' "$1" | nc -w2 127.0.0.1 "$PORT" 2>/dev/null; sleep 0.2; }

count_id() { grep -ac "id \"$1\"" "$ERRLOG" 2>/dev/null; }
last_id()  { grep -a "id \"$1\"" "$ERRLOG" 2>/dev/null | tail -1; }
any_id()   { grep -aoE '\[id "[0-9]{6}"\]' "$ERRLOG" 2>/dev/null | grep -oE '[0-9]{6}' | sort -u | tr '\n' ' '; }

assert_eq() { # desc expected actual
    _log "  (actual=$3 expected=$2)"
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (기대 '$2' / 실제 '$3')"; fi
}
assert_fired() { # id desc
    local n; n="$(count_id "$1")"
    [ -n "$(last_id "$1")" ] && printf 'LOG %s\n' "$(last_id "$1")" >> "$CURRENT_LOG"
    if [ "$n" -ge 1 ]; then pass "$2 (id $1 매칭)"; else fail "$2 (id $1 미발견)"; fi
}
assert_any_fired() { # "id1 id2 ..." desc
    local ids="$1" desc="$2" found=""
    local i
    for i in $ids; do [ "$(count_id "$i")" -ge 1 ] && found="$found $i"; done
    [ -n "$found" ] && printf 'LOG fired:%s\n' "$found" >> "$CURRENT_LOG"
    if [ -n "$found" ]; then pass "$desc (매칭:$found)"; else fail "$desc (해당 id 미발견)"; fi
}

cleanup_artifacts() { rm -f "$CONF_DIR"/crs-t9-*.conf; return 0; }
