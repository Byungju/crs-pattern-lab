#!/usr/bin/env bash
#
# verify.sh - REQUEST-921-PROTOCOL-ATTACK.conf 룰 검증
#
# 사용법:
#   ./verify.sh all
#   ./verify.sh 921120
#
# detection/blocking PL=4 설정으로 모든 PL 룰을 실행/차단한다.
#
set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HARNESS_DIR/lib.sh"

ALL_IDS=(
  921011
  921012
  921013
  921014
  921015
  921016
  921017
  921018
  921110
  921120
  921130
  921140
  921150
  921151
  921160
  921170
  921180
  921190
  921200
  921210
  921220
  921230
  921240
  921250
  921421
  921422
)

U="http://127.0.0.1:$PORT"

c_921110() { info "파라미터 내 요청 스머글링 패턴"; assert_eq "921110 → 403" 403 "$(curl_code "$U/?x=GET%20/%20http/1.1")"; assert_fired 921110 "921110: Request Smuggling"; }
c_921120() { info "파라미터 내 CRLF + set-cookie"; assert_eq "921120 → 403" 403 "$(curl_code "$U/?x=foo%0d%0aset-cookie:%20abc")"; assert_fired 921120 "921120: Response Splitting"; }
c_921130() { info "파라미터 내 <html"; assert_eq "921130 → 403" 403 "$(curl_code "$U/?x=<html>")"; assert_fired 921130 "921130: Response Splitting"; }
c_921150() { info "파라미터 이름(ARGS_NAMES)에 CRLF"; assert_eq "921150 → 403" 403 "$(curl_code "$U/?a%0d%0ab=1")"; assert_fired 921150 "921150: Header Injection (CR/LF)"; }
c_921151() { info "파라미터 값에 CRLF"; assert_eq "921151 → 403" 403 "$(curl_code "$U/?x=foo%0d%0aBar:baz")"; assert_fired 921151 "921151: Header Injection (CR/LF)"; }
c_921160() { info "파라미터에 CRLF + set-cookie"; assert_eq "921160 → 403" 403 "$(curl_code "$U/?x=foo%0d%0aset-cookie:%20abc")"; assert_fired 921160 "921160: Header Injection (CR/LF+name)"; }
c_921180() { info "파라미터 중복(HPP)"; assert_eq "921180 → 403" 403 "$(curl_code "$U/?a=1&a=2")"; assert_fired 921180 "921180: HTTP Parameter Pollution"; }
c_921190() { info "경로(REQUEST_FILENAME)에 CRLF"; assert_eq "921190 → 403" 403 "$(curl_code "$U/foo%0aBar")"; assert_fired 921190 "921190: Splitting (CR/LF in filename)"; }
c_921200() { info "LDAP Injection 패턴"; assert_eq "921200 → 403" 403 "$(curl_code "$U/?q=*)(uid=*)(|(cn=*")"; assert_fired 921200 "921200: LDAP Injection"; }
c_921220() { info "배열 표기 파라미터(HPP)"; assert_eq "921220 → 403" 403 "$(curl_code "$U/?a[]=1&a[]=2")"; assert_fired 921220 "921220: HPP via array notation"; }
c_921230() { info "Range 헤더"; assert_eq "921230 → 403" 403 "$(curl_code -H 'Range: bytes=0-1' "$U/")"; assert_fired 921230 "921230: HTTP Range Header"; }
c_921240() { info "unix:...| (mod_proxy)"; assert_eq "921240 → 403" 403 "$(curl_code "$U/?x=unix:/tmp/sock|")"; assert_fired 921240 "921240: mod_proxy attack"; }
c_921250() { info "Old Cookie V1"; assert_eq "921250 → 403" 403 "$(curl_code -H 'Cookie: $Version=1; a=b' "$U/")"; assert_fired 921250 "921250: Old Cookies V1"; }
c_921421() { info "위험한 Content-Type 조합(공백+json)"; assert_eq "921421 → 403" 403 "$(curl_code -H 'Content-Type: x application/json' --data '{}' "$U/")"; assert_fired 921421 "921421: dangerous content type"; }
c_921422() { info "위험한 Content-Type 조합(세미콜론+xml)"; assert_eq "921422 → 403" 403 "$(curl_code -H 'Content-Type: application/x-www-form-urlencoded;application/xml' --data 'a=1' "$U/")"; assert_fired 921422 "921422: dangerous content type"; }

dispatch() {
    local id="$1"
    case "$id" in
        921110) c_921110 ;;
        921120) c_921120 ;;
        921130) c_921130 ;;
        921150) c_921150 ;;
        921151) c_921151 ;;
        921160) c_921160 ;;
        921180) c_921180 ;;
        921190) c_921190 ;;
        921200) c_921200 ;;
        921220) c_921220 ;;
        921230) c_921230 ;;
        921240) c_921240 ;;
        921250) c_921250 ;;
        921421) c_921421 ;;
        921422) c_921422 ;;
        921170) skip "921170: helper 룰(ARGS_NAMES 카운트, 921180 의 전구 룰) — nolog" ;;
        *) skip "$id: 공격 예제 미구현 (nginx 도달 불가 또는 조건 필요)" ;;
    esac
}

run_one() {
    local id="$1"
    CURRENT_LOG="$TEST_LOG_DIR/$id.log"
    {
        printf '# rule %s\n' "$id"
        printf '# date %s\n' "$(date '+%F %T')"
        printf '# file REQUEST-921-PROTOCOL-ATTACK.conf\n\n'
    } > "$CURRENT_LOG"
    printf '\n[%s] %s\n' "$id" "REQUEST-921-PROTOCOL-ATTACK.conf"
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
