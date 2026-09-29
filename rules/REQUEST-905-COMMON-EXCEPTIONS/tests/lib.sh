#!/usr/bin/env bash
# lib.sh - REQUEST-905-COMMON-EXCEPTIONS 검증 하네스 공용 라이브러리
#
# 905 파일은 "예외(화이트리스트)" 룰이라 공격을 차단하지 않는다.
# 로컬 헬스체크 요청에 대해 CRS 룰을 제거(ruleRemoveByTag)하고 audit 을 끄는 효과를 검증한다.
#
# 검증 방식:
#   - 920350(Host numeric IP) 을 "탐지 표식"으로 사용한다.
#       · 예외가 적용되면 OWASP_CRS 룰이 제거되어 920350 이 사라진다.
#       · 예외가 미적용이면 920350 이 기록된다.
#   - 테스트 전용 probe 룰로 요청이 처리되었음을 확인하고, SecAuditEngine On 으로 audit 도 함께 본다.

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="${LAB:-/home/ubuntu/web_security}"
NGINX_PREFIX="$LAB/install/nginx"
NGINX="$NGINX_PREFIX/sbin/nginx"
CONF_DIR="$NGINX_PREFIX/conf"
CRS_DIR="$CONF_DIR/crs"

# 프로젝트 루트(crs-pattern-lab) 기준의 임시 테스트 로그 디렉토리
PROJECT_ROOT="$(cd "$HARNESS_DIR/../../.." && pwd)"
LOG_SUBDIR="REQUEST-905-COMMON-EXCEPTIONS"
TEST_LOG_DIR="$PROJECT_ROOT/logs/local_test/$LOG_SUBDIR"
mkdir -p "$TEST_LOG_DIR"

PORT="${PORT:-8100}"
PROBE_PATH="/__crs_905_probe"

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

ERRLOG="$TEST_LOG_DIR/nginx-error.log"
AUDITLOG="$TEST_LOG_DIR/nginx-audit.log"

gen_conf() {
    cat > "$CONF_DIR/crs-t905-probe.conf" <<'EOF'
# 테스트 전용 probe (CRS 룰 아님, OWASP_CRS 태그 없음)
# 905110 이 OWASP_CRS 룰을 제거해도 이 룰은 남아 요청 처리 사실을 로그로 남긴다.
SecAction "id:9900051,phase:2,pass,log,auditlog,msg:'T905 request_line=[%{request_line}] ua=[%{request_headers.user-agent}] remote=%{remote_addr}'"
EOF
    cat > "$CONF_DIR/crs-t905-modsec.conf" <<EOF
Include $CONF_DIR/modsecurity.conf
Include $CONF_DIR/crs-t905-probe.conf
SecAuditEngine On
SecAuditLog $AUDITLOG
SecAuditLogType Serial
SecAuditLogParts ABIJDEFHZ
EOF
    cat > "$CONF_DIR/crs-t905-nginx.conf" <<EOF
worker_processes 1;
error_log $ERRLOG info;
pid $TEST_LOG_DIR/nginx.pid;
events { worker_connections 64; }
http {
    include mime.types;
    default_type application/octet-stream;
    modsecurity on;
    modsecurity_rules_file $CONF_DIR/crs-t905-modsec.conf;
    server {
        listen 127.0.0.1:$PORT;
        location / { root html; index index.html; }
        location = $PROBE_PATH { return 200 "ok\n"; }
    }
}
EOF
}

start_nginx() {
    stop_nginx
    "$NGINX" -p "$NGINX_PREFIX" -c "$CONF_DIR/crs-t905-nginx.conf" 2>/dev/null
    local i
    for i in $(seq 1 30); do
        [ "$(http_code "/")" != "000" ] && break
        sleep 0.1
    done
    sleep 0.2
}
stop_nginx() {
    "$NGINX" -p "$NGINX_PREFIX" -c "$CONF_DIR/crs-t905-nginx.conf" -s stop 2>/dev/null || true
    sleep 0.2
}

# 요청: Host: 127.0.0.1(numeric) 로 920350 을 유발. remote_addr 는 127.0.0.1(예외 조건 충족).
do_request() { # path  user_agent
    local path="$1" ua="$2"
    : > "$ERRLOG"; : > "$AUDITLOG"
    curl -s -o /dev/null -m 5 -H 'Host: 127.0.0.1' -A "$ua" \
        "http://127.0.0.1:$PORT$path" 2>/dev/null
    sleep 0.2
}
http_code() { curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$PORT$1" 2>/dev/null; }

count_920350() { grep -ac 'id "920350"' "$ERRLOG" 2>/dev/null; }
audit_count()  { grep -acE '^---[A-Za-z0-9]+---A--' "$AUDITLOG" 2>/dev/null; }
probe_line()   { grep -a 'T905 ' "$ERRLOG" 2>/dev/null | tail -1; }

assert_eq() { # desc expected actual
    _log "  (actual=$3 expected=$2)"
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1 (기대 '$2' / 실제 '$3')"
    fi
}

cleanup_artifacts() {
    rm -f "$CONF_DIR"/crs-t905-*.conf
    # 로그는 logs/local_test/REQUEST-905-COMMON-EXCEPTIONS/ 에 그대로 보존한다.
    return 0
}
