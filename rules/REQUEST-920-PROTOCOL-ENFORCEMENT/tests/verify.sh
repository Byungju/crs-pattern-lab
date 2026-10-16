#!/usr/bin/env bash
#
# verify.sh - REQUEST-920-PROTOCOL-ENFORCEMENT.conf 룰 검증
#
# 사용법:
#   ./verify.sh all
#   ./verify.sh 920420
#
# 주의: nginx 가 CRS 도달 전에 400/405 로 막는 요청이 많아, 이 환경에서
#       트리거 가능한 룰만 공격 예제로 검증한다. 나머지는 SKIP(사유 표기).
#
set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HARNESS_DIR/lib.sh"

ALL_IDS=(
  920011
  920012
  920013
  920014
  920015
  920016
  920017
  920018
  920100
  920120
  920121
  920160
  920170
  920171
  920180
  920181
  920190
  920200
  920201
  920202
  920210
  920230
  920240
  920250
  920260
  920270
  920271
  920272
  920273
  920274
  920275
  920280
  920290
  920300
  920310
  920311
  920320
  920330
  920340
  920350
  920360
  920370
  920380
  920390
  920400
  920410
  920420
  920430
  920440
  920450
  920451
  920460
  920470
  920480
  920490
  920500
  920510
  920520
  920521
  920530
  920539
  920540
  920600
  920610
  920620
  920640
  920650
  920660
)

# --- 구현된 공격 예제 ---
c_920120() { info "multipart 파일명에 구분자 문자(;) 포함 → bypass 시도"; assert_eq "920120 → 403" 403 "$(mp_code 'multipart/form-data; boundary=X|--X\r\nContent-Disposition: form-data; name="f"; filename="a;b.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n--X--\r\n')"; assert_fired 920120 "920120: multipart/form-data bypass"; }
c_920100() {
    info "A) nginx가 통과시키지만 RFC 형식을 벗어나는 요청 라인 → 920100 발동"
    info "   요청: TOOLONGMETHODX / HTTP/1.1   (메서드 13자 > regex 한도 10자)"
    assert_eq "920100 → 403" 403 "$(raw_code 'TOOLONGMETHODX / HTTP/1.1\r\nHost: x\r\n\r\n')"
    assert_fired 920100 "920100: Invalid HTTP Request Line"

    info "B) nginx가 파싱 단계에서 먼저 거부하는 요청 라인 → CRS(920100) 도달 못 함"
    info "   요청: GET /\\x01 HTTP/1.1   (제어문자 포함 → nginx 400)"
    : > "$ERRLOG"
    printf 'GET /\x01 HTTP/1.1\r\nHost: x\r\n\r\n' | nc -w2 127.0.0.1 "$PORT" >/dev/null 2>&1
    sleep 0.2
    local ne na
    ne="$(grep -a 'client sent invalid request' "$ERRLOG" | tail -1)"
    [ -n "$ne" ] && printf 'NGINX-ERROR %s\n' "$ne" >> "$CURRENT_LOG"
    if [ -n "$ne" ]; then pass "nginx error 로그에 기록됨('client sent invalid request')"; else fail "nginx error 로그 없음"; fi
    na="$(grep -a ' 400 ' "$TEST_LOG_DIR/nginx-access.log" | tail -1)"
    [ -n "$na" ] && printf 'NGINX-ACCESS %s\n' "$na" >> "$CURRENT_LOG"
    assert_eq "B) 920100 미발동(nginx 선차단)" "0" "$(count_id 920100)"
    info "로그: $TEST_LOG_DIR/{nginx-error.log,nginx-access.log,<id>.log}  (CRS=920100 로그, nginx=자체 로그)"
}
c_920280() { info "Host 헤더 없는 HTTP/1.0 요청"; assert_eq "920280 → 403" 403 "$(raw_code 'GET / HTTP/1.0\r\n\r\n')"; assert_fired 920280 "920280: Missing Host Header"; }
c_920330() { info "빈 User-Agent 헤더"; raw_code "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent:\r\n\r\n" >/dev/null; assert_fired 920330 "920330: Empty User Agent"; }
c_920350() { info "Host 가 숫자 IP"; curl_code -H 'Host: 127.0.0.1' "http://127.0.0.1:$PORT/" >/dev/null; assert_fired 920350 "920350: Host numeric IP"; }
c_920420() { info "정책 외 Content-Type(text/plain)"; assert_eq "920420 → 403" 403 "$(curl_code -H 'Content-Type: text/plain' --data 'a=1' "http://127.0.0.1:$PORT/")"; assert_fired 920420 "920420: content-type not allowed"; }
c_920440() { info "금지 확장자(.bak)"; assert_eq "920440 → 403" 403 "$(curl_code "http://127.0.0.1:$PORT/x.bak")"; assert_fired 920440 "920440: restricted extension"; }
c_920450() { info "금지 헤더(Proxy)"; assert_eq "920450 → 403" 403 "$(curl_code -H 'Proxy: 1' "http://127.0.0.1:$PORT/")"; assert_fired 920450 "920450: restricted header"; }
c_920480() { info "정책 외 charset(utf-16)"; assert_eq "920480 → 403" 403 "$(curl_code -H 'Content-Type: application/json; charset=utf-16' --data '{}' "http://127.0.0.1:$PORT/")"; assert_fired 920480 "920480: charset not allowed"; }
c_920600() { info "잘못된 Accept charset"; assert_eq "920600 → 403" 403 "$(curl_code -H 'Accept: text/html; charset=foo-bar' "http://127.0.0.1:$PORT/")"; assert_fired 920600 "920600: illegal accept charset"; }
c_920620() { info "Content-Type 헤더 중복"; assert_eq "920620 → 403" 403 "$(raw_code "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Type: a\r\nContent-Type: b\r\nContent-Length: 0\r\n\r\n")"; assert_fired 920620 "920620: multiple Content-Type"; }

dispatch() {
    local id="$1"
    case "$id" in
        920100) c_920100 ;;
        920120) c_920120 ;;
        920280) c_920280 ;;
        920330) c_920330 ;;
        920350) c_920350 ;;
        920420) c_920420 ;;
        920440) c_920440 ;;
        920450) c_920450 ;;
        920480) c_920480 ;;
        920600) c_920600 ;;
        920620) c_920620 ;;
        *) skip "$id: 공격 예제 미구현 (nginx 도달 불가 또는 조건/설정 필요)" ;;
    esac
}

run_one() {
    local id="$1"
    CURRENT_LOG="$TEST_LOG_DIR/$id.log"
    {
        printf '# rule %s\n' "$id"
        printf '# date %s\n' "$(date '+%F %T')"
        printf '# file REQUEST-920-PROTOCOL-ENFORCEMENT.conf\n\n'
    } > "$CURRENT_LOG"
    printf '\n[%s] %s\n' "$id" "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"
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
