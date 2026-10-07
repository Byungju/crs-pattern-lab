#!/usr/bin/env bash
# lib.sh - REQUEST-913-SCANNER-DETECTION 검증 하네스 공용 라이브러리
#
# 913100 은 User-Agent 가 알려진 스캐너 목록(scanners-user-agents.data)에 매칭되면
# 점수(CRITICAL=5)를 누적하고, 949110 이 403 으로 차단한다.
#
# 공격 예제: 스캐너 User-Agent (sqlmap, nikto, nmap, nuclei, masscan ...)

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="${LAB:-/home/ubuntu/web_security}"
NGINX_PREFIX="$LAB/install/nginx"
NGINX="$NGINX_PREFIX/sbin/nginx"
CONF_DIR="$NGINX_PREFIX/conf"
CRS_DIR="$CONF_DIR/crs"

# 프로젝트 루트(crs-pattern-lab) 기준의 임시 테스트 로그 디렉토리
PROJECT_ROOT="$(cd "$HARNESS_DIR/../../.." && pwd)"
LOG_SUBDIR="REQUEST-913-SCANNER-DETECTION"
TEST_LOG_DIR="$PROJECT_ROOT/logs/local_test/$LOG_SUBDIR"
mkdir -p "$TEST_LOG_DIR"

PORT="${PORT:-8102}"
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
    cat > "$CONF_DIR/crs-t913-probe.conf" <<'EOF'
# 테스트 전용 probe (CRS 룰 아님)
SecAction "id:9900913,phase:2,pass,log,auditlog,msg:'T913 ua=[%{request_headers.user-agent}]'"
EOF
    cat > "$CONF_DIR/crs-t913-modsec.conf" <<EOF
Include $CONF_DIR/modsecurity.conf
Include $CONF_DIR/crs-t913-probe.conf
SecAuditEngine On
SecAuditLog $AUDITLOG
SecAuditLogType Serial
SecAuditLogParts ABIJDEFHZ
EOF
    cat > "$CONF_DIR/crs-t913-nginx.conf" <<EOF
worker_processes 1;
error_log $ERRLOG info;
pid $TEST_LOG_DIR/nginx.pid;
events { worker_connections 64; }
http {
    include mime.types;
    default_type application/octet-stream;
    modsecurity on;
    modsecurity_rules_file $CONF_DIR/crs-t913-modsec.conf;
    server {
        listen 127.0.0.1:$PORT;
        location / { root html; index index.html; }
    }
}
EOF
}

start_nginx() {
    stop_nginx
    "$NGINX" -p "$NGINX_PREFIX" -c "$CONF_DIR/crs-t913-nginx.conf" 2>/dev/null
    local i
    for i in $(seq 1 30); do
        [ "$(http_code "/" "Mozilla/5.0")" != "000" ] && break
        sleep 0.1
    done
    sleep 0.2
}
stop_nginx() {
    "$NGINX" -p "$NGINX_PREFIX" -c "$CONF_DIR/crs-t913-nginx.conf" -s stop 2>/dev/null || true
    sleep 0.2
}

# 요청 1회 (로그 초기화 후, HTTP 코드 출력). UA 는 공격 예제의 핵심.
do_request() { # path  user_agent
    : > "$ERRLOG"; : > "$AUDITLOG"
    curl -s -o /dev/null -m 5 -w '%{http_code}' -A "$2" -H 'Host: localhost' "http://127.0.0.1:$PORT$1" 2>/dev/null
    sleep 0.2
}
http_code() { curl -s -o /dev/null -m 5 -w '%{http_code}' -A "$2" -H 'Host: localhost' "http://127.0.0.1:$PORT$1" 2>/dev/null; }

count_id()    { grep -ac "id \"$1\"" "$ERRLOG" 2>/dev/null; }
audit_count() { grep -acE '^---[A-Za-z0-9]+---A--' "$AUDITLOG" 2>/dev/null; }
last_913100() { grep -a 'id "913100"' "$ERRLOG" 2>/dev/null | tail -1; }

assert_eq() { # desc expected actual
    _log "  (actual=$3 expected=$2)"
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (기대 '$2' / 실제 '$3')"; fi
}

cleanup_artifacts() {
    rm -f "$CONF_DIR"/crs-t913-*.conf
    # 로그는 logs/local_test/REQUEST-913-SCANNER-DETECTION/ 에 보존한다.
    return 0
}
