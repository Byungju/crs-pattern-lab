#!/usr/bin/env bash
#
# verify.sh - REQUEST-911-METHOD-ENFORCEMENT.conf 룰 검증
#
# 사용법:
#   ./verify.sh all
#   ./verify.sh 911100
#
# 911100: 정책(tx.allowed_methods)에 없는 메서드 → CRS 차단(403).
#   공격 예제: PUT / DELETE / PATCH  (허용: GET / HEAD)
#
set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HARNESS_DIR/lib.sh"

ALL_IDS=(911011 911012 911013 911014 911015 911016 911017 911018 911100)

assert_ge() { # desc expected_min actual
    _log "  (actual=$3 min=$2)"
    if [ "$3" -ge "$2" ] 2>/dev/null; then pass "$1"; else fail "$1 (>= $2 기대 / 실제 $3)"; fi
}

# 공격 예제: 허용되지 않은 메서드 → 911100 탐지 + 949110 차단(403)
check_method_denied() {
    local m="$1" code
    code="$(do_request "$m" "/")"
    [ -n "$(last_911100)" ] && printf 'LOG %s\n' "$(last_911100)" >> "$CURRENT_LOG"
    assert_eq "911100 [$m]: 미허용 메서드 → 403 차단" "403" "$code"
    assert_ge "911100 [$m]: 룰 매칭 로그" "1" "$(count_id 911100)"
    assert_ge "911100 [$m]: 949110(차단 평가) 동반" "1" "$(count_id 949110)"
}

check_method_allowed() {
    local m="$1" code
    code="$(do_request "$m" "/")"
    assert_eq "911100 [$m]: 허용 메서드 → 통과(200)" "200" "$code"
    assert_eq "911100 [$m]: 룰 미매칭" "0" "$(count_id 911100)"
}

case_911100() {
    info "911100: Method is not allowed by policy (기본 허용: GET HEAD POST OPTIONS)"
    info "-- 공격 예제(미허용 메서드) --"
    check_method_denied PUT
    check_method_denied DELETE
    check_method_denied PATCH
    info "-- 정상(허용 메서드) 대조군 --"
    check_method_allowed GET
    check_method_allowed HEAD
}

# PL 게이팅 보조 룰 (탐지 아님)
case_pl_gate() {
    skip "$1: PL 게이팅(skipAfter) 보조 룰 — 공격 탐지 대상 아님 (911100 실행 여부 제어)"
}

dispatch() {
    case "$1" in
        911100) case_911100 ;;
        911011|911012|911013|911014|911015|911016|911017|911018) case_pl_gate "$1" ;;
        *) fail "알 수 없는 룰 id: $1" ;;
    esac
}

run_one() {
    local id="$1"
    CURRENT_LOG="$TEST_LOG_DIR/$id.log"
    {
        printf '# rule %s\n' "$id"
        printf '# date %s\n' "$(date '+%F %T')"
        printf '# file REQUEST-911-METHOD-ENFORCEMENT.conf\n\n'
    } > "$CURRENT_LOG"
    printf '\n[%s] %s\n' "$id" "REQUEST-911-METHOD-ENFORCEMENT.conf"
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
