#!/usr/bin/env bash
#
# verify.sh - REQUEST-913-SCANNER-DETECTION.conf 룰 검증
#
# 사용법:
#   ./verify.sh all
#   ./verify.sh 913100
#
# 913100: User-Agent 가 알려진 스캐너 목록에 매칭되면 CRS 차단(403).
#   공격 예제: sqlmap / nikto / nmap / nuclei 등 (정상: Mozilla, Googlebot)
#
set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HARNESS_DIR/lib.sh"

ALL_IDS=(913100)

assert_ge() { # desc expected_min actual
    _log "  (actual=$3 min=$2)"
    if [ "$3" -ge "$2" ] 2>/dev/null; then pass "$1"; else fail "$1 (>= $2 기대 / 실제 $3)"; fi
}

# 공격 예제: 스캐너 User-Agent → 913100 탐지 + 949110 차단(403)
check_scanner_denied() {
    local ua="$1" code
    code="$(do_request "/" "$ua")"
    [ -n "$(last_913100)" ] && printf 'LOG %s\n' "$(last_913100)" >> "$CURRENT_LOG"
    assert_eq "913100 [${ua:0:20}]: 스캐너 UA → 403 차단" "403" "$code"
    assert_ge "913100 [${ua:0:20}]: 룰 매칭 로그" "1" "$(count_id 913100)"
    assert_ge "913100 [${ua:0:20}]: 949110(차단 평가) 동반" "1" "$(count_id 949110)"
}

# 대조군: 정상 User-Agent → 통과
check_normal_allowed() {
    local ua="$1" code
    code="$(do_request "/" "$ua")"
    assert_eq "913100 [${ua:0:20}]: 정상 UA → 통과(200)" "200" "$code"
    assert_eq "913100 [${ua:0:20}]: 룰 미매칭" "0" "$(count_id 913100)"
}

case_913100() {
    info "913100: Found User-Agent associated with security scanner (pmFromFile scanners-user-agents.data)"
    info "-- 대표 예제(실제 UA 형태, 부분 일치 확인) --"
    check_scanner_denied "sqlmap/1.7.2#stable"
    check_scanner_denied "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
    check_scanner_denied "Nuclei - Open Source Vulnerability Scanner (https://nuclei.projectdiscovery.io)"
    info "-- 정상 대조군 --"
    check_normal_allowed "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    check_normal_allowed "Googlebot/2.1 (+http://www.google.com/bot.html)"

    info "-- 목록 전체 스윕(패턴마다 UA=패턴 으로 전송) --"
    local data="$CRS_DIR/rules/scanners-user-agents.data"
    if [ ! -f "$data" ]; then
        fail "913100: 스캐너 목록 파일 없음 ($data)"
        return
    fi
    local -a pats=()
    mapfile -t pats < <(grep -vE '^[[:space:]]*(#|$)' "$data" | sed -e 's/[[:space:]]*$//')
    info "   대상 패턴 수: ${#pats[@]}"
    local ua
    for ua in "${pats[@]}"; do
        check_scanner_denied "$ua"
    done
}

dispatch() {
    case "$1" in
        913100) case_913100 ;;
        *) fail "알 수 없는 룰 id: $1" ;;
    esac
}

run_one() {
    local id="$1"
    CURRENT_LOG="$TEST_LOG_DIR/$id.log"
    {
        printf '# rule %s\n' "$id"
        printf '# date %s\n' "$(date '+%F %T')"
        printf '# file REQUEST-913-SCANNER-DETECTION.conf\n\n'
    } > "$CURRENT_LOG"
    printf '\n[%s] %s\n' "$id" "REQUEST-913-SCANNER-DETECTION.conf"
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
