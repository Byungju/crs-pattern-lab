#!/usr/bin/env bash
#
# verify.sh - REQUEST-905-COMMON-EXCEPTIONS.conf 룰 검증
#
# 사용법:
#   ./verify.sh all
#   ./verify.sh 905110
#
# 905 파일은 예외(화이트리스트) 룰이다. 로컬 요청에 대해
#   ctl:ruleRemoveByTag=OWASP_CRS  (CRS 룰 제거)
#   ctl:auditEngine=Off            (audit 비활성)
# 효과를, 920350(Host numeric IP) 탐지를 표식으로 검증한다.
#
set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HARNESS_DIR/lib.sh"

ALL_IDS=(905100 905110)

# 905100: Apache SSL pinger 예외
#   조건 = REQUEST_LINE @streq "GET /"  AND  REMOTE_ADDR @ipMatch 127.0.0.1,::1
case_905100() {
    info "905100: Apache SSL pinger 예외 — GET / + 로컬주소이면 CRS 제거 시도"
    do_request "/" "Apache"
    local rl; rl="$(probe_line)"
    [ -n "$CURRENT_LOG" ] && printf 'PROBE %s\n' "$rl" >> "$CURRENT_LOG"
    info "실제 REQUEST_LINE: $(printf '%s' "$rl" | sed -n 's/.*request_line=\[\([^]]*\)\].*/\1/p')"
    info "→ REQUEST_LINE 은 'GET / HTTP/1.1'(프로토콜 포함)이라 '@streq GET /' 와 불일치"
    info "→ 이 환경(nginx/ModSecurity v3)에서는 905100 이 발동하지 않음 (920350=$(count_920350) 로 확인)"
    skip "905100: 조건(@streq GET /) 불일치로 실환경 미발동 — 발동 검증 불가"
}

# 905110: Apache internal dummy connection 예외
case_905110() {
    info "905110: internal dummy connection 예외 (로컬 + UA suffix + GET /|OPTIONS *)"

    info "[트리거] UA='Apache (internal dummy connection)', GET /"
    do_request "/" "Apache (internal dummy connection)"
    assert_eq "905110 트리거: CRS 제거(920350 사라짐)" "0" "$(count_920350)"
    assert_eq "905110 트리거: auditEngine=Off(audit 미기록)" "0" "$(audit_count)"
    [ -n "$(probe_line)" ] && info "요청은 정상 처리됨(probe 로그 존재)"

    info "[대조군1] REQUEST_LINE 다름(/)→/x"
    do_request "/x" "Apache (internal dummy connection)"
    assert_eq "905110 대조군1: REQUEST_LINE 불일치 → 예외 미적용(920350=1)" "1" "$(count_920350)"

    info "[대조군2] UA suffix 없음"
    do_request "/" "Apache"
    assert_eq "905110 대조군2: UA 불일치 → 예외 미적용(920350=1)" "1" "$(count_920350)"
}

dispatch() {
    case "$1" in
        905100) case_905100 ;;
        905110) case_905110 ;;
        *) fail "알 수 없는 룰 id: $1" ;;
    esac
}

run_one() {
    local id="$1"
    CURRENT_LOG="$TEST_LOG_DIR/$id.log"
    {
        printf '# rule %s\n' "$id"
        printf '# date %s\n' "$(date '+%F %T')"
        printf '# file REQUEST-905-COMMON-EXCEPTIONS.conf\n\n'
    } > "$CURRENT_LOG"
    printf '\n[%s] %s\n' "$id" "REQUEST-905-COMMON-EXCEPTIONS.conf"
    dispatch "$id"
    CURRENT_LOG=""
}

main() {
    mkdir -p "$TEST_LOG_DIR"
    [ -x "$NGINX" ] || { echo "nginx 없음: $NGINX"; exit 1; }
    [ -f "$CONF_DIR/modsecurity.conf" ] || { echo "modsecurity.conf 없음"; exit 1; }

    local targets=("$@")
    [ ${#targets[@]} -eq 0 ] && targets=("all")
    [ "${targets[0]}" = "all" ] && targets=("${ALL_IDS[@]}")

    gen_conf
    start_nginx

    local id
    for id in "${targets[@]}"; do run_one "$id"; done

    stop_nginx
    cleanup_artifacts

    printf '\n%s\n' "----------------------------------------"
    printf 'PASS=%d  FAIL=%d  SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
    [ "$FAIL" -eq 0 ]
}

main "$@"
