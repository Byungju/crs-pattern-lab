#!/usr/bin/env bash
# lib.sh - REQUEST-901-INITIALIZATION 검증 하네스 공용 라이브러리
#
# 실제 nginx(install/nginx)를 테스트용 설정으로 기동하여
# CRS 초기화 룰(901xxx)이 TX 변수를 기대값으로 세팅하는지 확인한다.
#
# 검증 방식:
#   - 대부분의 901 룰은 nolog 변수 세팅 룰이므로, 테스트 전용 probe 룰(9900001)로
#     TX 변수 값을 error log 에 출력하게 하고 값을 비교한다.
#   - 로그를 남기는 룰(901001, 901500 등)은 별도 설정 인스턴스를 띄워
#     응답 코드와 로그를 확인한다.

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="${LAB:-/home/ubuntu/web_security}"
NGINX_PREFIX="$LAB/install/nginx"
NGINX="$NGINX_PREFIX/sbin/nginx"
CONF_DIR="$NGINX_PREFIX/conf"
CRS_DIR="$CONF_DIR/crs"

# 프로젝트 루트(crs-pattern-lab) 기준의 임시 테스트 로그 디렉토리
PROJECT_ROOT="$(cd "$HARNESS_DIR/../../.." && pwd)"
LOG_SUBDIR="REQUEST-901-INITIALIZATION"
TEST_LOG_DIR="$PROJECT_ROOT/logs/local_test/$LOG_SUBDIR"
mkdir -p "$TEST_LOG_DIR"

MAIN_PORT="${MAIN_PORT:-8091}"
VARIANT_PORT_1="${VARIANT_PORT_1:-8092}"
VARIANT_PORT_2="${VARIANT_PORT_2:-8093}"
PROBE_PATH="/__crs_probe"

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

# ---------------------------------------------------------------------------
# probe / 설정 파일 생성
# ---------------------------------------------------------------------------
gen_probe_conf() {
    cat > "$CONF_DIR/crs-test-probe.conf" <<'EOF'
# 테스트 전용 probe (CRS 룰 아님). phase:2 에서 TX 초기화 변수를 error log 로 출력.
SecAction "id:9900001,phase:2,pass,log,auditlog,msg:'CRS_PROBE:setup=%{tx.crs_setup_version}:inbound_thr=%{tx.inbound_anomaly_score_threshold}:outbound_thr=%{tx.outbound_anomaly_score_threshold}:reporting=%{tx.reporting_level}:early=%{tx.early_blocking}:blocking_pl=%{tx.blocking_paranoia_level}:detection_pl=%{tx.detection_paranoia_level}:sampling=%{tx.sampling_percentage}:sampling_rnd100=%{tx.sampling_rnd100}:crit=%{tx.critical_anomaly_score}:error=%{tx.error_anomaly_score}:warning=%{tx.warning_anomaly_score}:notice=%{tx.notice_anomaly_score}:allowed_methods=%{tx.allowed_methods}:allowed_ct=%{tx.allowed_request_content_type}:allowed_http=%{tx.allowed_http_versions}:allowed_charset=%{tx.allowed_request_content_type_charset}:restricted_ext=%{tx.restricted_extensions}:restricted_hdr_basic=%{tx.restricted_headers_basic}:restricted_hdr_ext=%{tx.restricted_headers_extended}:method_override=%{tx.allow_method_override_parameter}:enforce_urlenc=%{tx.enforce_bodyproc_urlencoded}:utf8=%{tx.crs_validate_utf8_encoding}:skip_resp=%{tx.crs_skip_response_analysis}:score_in=%{tx.blocking_inbound_anomaly_score}:score_det_in=%{tx.detection_inbound_anomaly_score}:score_out=%{tx.blocking_outbound_anomaly_score}:sql=%{tx.sql_injection_score}:proc=%{reqbody_processor}:reqbody=%{request_body}:END'"
EOF
    # 테스트 전용 audit 로깅: modsecurity.conf 의 RelevantOnly 를 On 으로 덮어써
    # 룰이 매칭되지 않는 요청(정적 200, 404 probe 등)까지 모두 audit 로그에 남긴다.
    cat >> "$CONF_DIR/crs-test-probe.conf" <<EOF
SecAuditEngine On
SecAuditLog $TEST_LOG_DIR/nginx-audit.log
SecAuditLogType Serial
SecAuditLogParts ABIJDEFHZ
EOF
}

write_nginx_conf() {
    local file="$1" port="$2" errlog="$3" pidfile="$4" modsec="$5"
    cat > "$file" <<EOF
worker_processes 1;
error_log $errlog info;
pid $pidfile;
events { worker_connections 128; }
http {
    include mime.types;
    default_type application/octet-stream;
    modsecurity on;
    modsecurity_rules_file $modsec;
    server {
        listen 127.0.0.1:$port;
        location / { root html; index index.html; }
    }
}
EOF
}

gen_main_conf() {
    gen_probe_conf
    cat > "$CONF_DIR/crs-test-modsec.conf" <<EOF
Include $CONF_DIR/modsecurity.conf
Include $CONF_DIR/crs-test-probe.conf
EOF
    write_nginx_conf "$CONF_DIR/crs-test-nginx.conf" "$MAIN_PORT" \
        "$TEST_LOG_DIR/nginx-error.log" "$TEST_LOG_DIR/nginx.pid" "$CONF_DIR/crs-test-modsec.conf"
}

# 901340 처럼 nolog/noauditlog 라 로그가 없는 룰을 디버그 로그(level 9)로 확인
gen_debug_conf() { # conf_name pid/log tag
    local tag="$1" port="$2"
    cat > "$CONF_DIR/crs-test-modsec-$tag.conf" <<EOF
Include $CONF_DIR/modsecurity.conf
SecAuditEngine On
SecAuditLog $TEST_LOG_DIR/nginx-$tag-audit.log
SecAuditLogType Serial
SecDebugLog $TEST_LOG_DIR/nginx-$tag-debug.log
SecDebugLogLevel 9
EOF
    write_nginx_conf "$CONF_DIR/crs-test-nginx-$tag.conf" "$port" \
        "$TEST_LOG_DIR/nginx-$tag-error.log" "$TEST_LOG_DIR/nginx-$tag.pid" "$CONF_DIR/crs-test-modsec-$tag.conf"
}

# CRS rules 만 로드하고 crs-setup.conf 를 누락시킨 설정 (901001 트리거)
gen_nosetup_conf() {
    cat > "$CONF_DIR/crs-test-modsec-nosetup.conf" <<EOF
SecRuleEngine On
SecRequestBodyAccess On
SecTmpDir /tmp/
SecDataDir /tmp/
SecUnicodeMapFile $CONF_DIR/unicode.mapping 20127
SecAuditEngine On
SecAuditLog $TEST_LOG_DIR/nginx-nosetup-audit.log
SecAuditLogType Serial
Include $CRS_DIR/rules/*.conf
EOF
    write_nginx_conf "$CONF_DIR/crs-test-nginx-nosetup.conf" "$VARIANT_PORT_1" \
        "$TEST_LOG_DIR/nginx-nosetup-error.log" "$TEST_LOG_DIR/nginx-nosetup.pid" "$CONF_DIR/crs-test-modsec-nosetup.conf"
}

# detection PL < blocking PL 로 강제한 설정 (901500 트리거)
gen_invalidpl_conf() {
    cat > "$CONF_DIR/crs-test-modsec-invalidpl.conf" <<EOF
SecRuleEngine On
SecRequestBodyAccess On
SecTmpDir /tmp/
SecDataDir /tmp/
SecUnicodeMapFile $CONF_DIR/unicode.mapping 20127
SecAuditEngine On
SecAuditLog $TEST_LOG_DIR/nginx-invalidpl-audit.log
SecAuditLogType Serial
SecAction "id:9900002,phase:1,pass,nolog,setvar:tx.crs_setup_version=4300,setvar:tx.blocking_paranoia_level=2,setvar:tx.detection_paranoia_level=1"
Include $CRS_DIR/rules/*.conf
EOF
    write_nginx_conf "$CONF_DIR/crs-test-nginx-invalidpl.conf" "$VARIANT_PORT_2" \
        "$TEST_LOG_DIR/nginx-invalidpl-error.log" "$TEST_LOG_DIR/nginx-invalidpl.pid" "$CONF_DIR/crs-test-modsec-invalidpl.conf"
}

# ---------------------------------------------------------------------------
# nginx 기동/종료
# ---------------------------------------------------------------------------
nginx_running() { # pidfile
    local pf="$NGINX_PREFIX/$1"
    [ -f "$pf" ] && kill -0 "$(cat "$pf" 2>/dev/null)" 2>/dev/null
}

start_nginx() { # nginx_conf
    local conf="$1"
    "$NGINX" -p "$NGINX_PREFIX" -c "$conf" 2>/dev/null
    # 포트 대기
    local i
    for i in $(seq 1 30); do
        "$NGINX" -p "$NGINX_PREFIX" -c "$conf" -t >/dev/null 2>&1 && break
        sleep 0.1
    done
    sleep 0.2
}

stop_nginx() { # nginx_conf
    "$NGINX" -p "$NGINX_PREFIX" -c "$1" -s stop 2>/dev/null || true
    sleep 0.2
}

main_start()   { stop_nginx "$CONF_DIR/crs-test-nginx.conf";         start_nginx "$CONF_DIR/crs-test-nginx.conf"; }
main_stop()    { stop_nginx "$CONF_DIR/crs-test-nginx.conf"; }
test_case_stop() {
    stop_nginx "$CONF_DIR/crs-test-nginx-nosetup.conf"
    stop_nginx "$CONF_DIR/crs-test-nginx-invalidpl.conf"
    stop_nginx "$CONF_DIR/crs-test-nginx-901340.conf"
    stop_nginx "$CONF_DIR/crs-test-nginx.conf"
}
cleanup_artifacts() {
    rm -f "$CONF_DIR"/crs-test-*.conf
    # 로그는 logs/local_test/REQUEST-901-INITIALIZATION/ 에 그대로 보존한다.
    return 0
}

# ---------------------------------------------------------------------------
# HTTP / probe
# ---------------------------------------------------------------------------
http_code() { # port path
    curl -s -o /dev/null -m 5 -w '%{http_code}' "http://127.0.0.1:$1$2" 2>/dev/null
}

# 메인 인스턴스로 probe 요청을 보냄 (Host: localhost 로 920350 점수 오염 방지)
probe_request() {
    local marker="p$$-$RANDOM"
    curl -s -o /dev/null -m 5 -H 'Host: localhost' \
        "http://127.0.0.1:$MAIN_PORT$PROBE_PATH?marker=$marker" 2>/dev/null
    sleep 0.2
}

probe_line() { # errlog
    grep -a 'CRS_PROBE:' "$1" 2>/dev/null | tail -1
}

probe_get() { # errlog key
    local val
    val="$(probe_line "$1" | sed -n "s/.*:${2}=\([^:]*\):.*/\1/p")"
    printf '%s' "$val"
}

assert_probe() { # key expected desc
    local key="$1" exp="$2" desc="${3:-$1}"
    local got line
    line="$(probe_line "$TEST_LOG_DIR/nginx-error.log")"
    got="$(probe_get "$TEST_LOG_DIR/nginx-error.log" "$key")"
    [ -n "$CURRENT_LOG" ] && printf 'PROBE %s\n' "$line" >> "$CURRENT_LOG"
    if [ "$got" = "$exp" ]; then
        pass "$desc ($key=$got)"
    else
        fail "$desc (기대 '$exp' / 실제 '$got')"
    fi
}

# 값이 너무 길어 전체 비교가 비현실적인 경우 부분 문자열 포함 여부만 확인
assert_probe_contains() { # key substr desc
    local key="$1" sub="$2" desc="${3:-$1}"
    local got line
    line="$(probe_line "$TEST_LOG_DIR/nginx-error.log")"
    got="$(probe_get "$TEST_LOG_DIR/nginx-error.log" "$key")"
    [ -n "$CURRENT_LOG" ] && printf 'PROBE %s\n' "$line" >> "$CURRENT_LOG"
    if [[ "$got" == *"$sub"* ]]; then
        pass "$desc (포함: $sub)"
    else
        fail "$desc ('$sub' 미포함 / 실제 '${got:0:120}...')"
    fi
}

assert_code() { # port path expected desc
    local got
    got="$(http_code "$1" "$2")"
    if [ "$got" = "$3" ]; then
        pass "$4 (HTTP $got)"
    else
        fail "$4 (기대 HTTP $3 / 실제 HTTP $got)"
    fi
}

assert_log_has() { # errlog pattern desc
    local line
    line="$(grep -a "$2" "$1" 2>/dev/null | tail -1)"
    [ -n "$CURRENT_LOG" ] && printf 'LOG %s\n' "$line" >> "$CURRENT_LOG"
    if [ -n "$line" ]; then
        pass "$3"
    else
        fail "$3 (로그에서 '$2' 미발견)"
    fi
}
