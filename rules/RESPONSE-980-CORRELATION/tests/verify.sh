#!/usr/bin/env bash
#
# verify.sh - CRS 룰 파일 검증 (범용, tests/harness.env + cases.tsv 기반)
#
# 사용법:
#   ./verify.sh all
#   ./verify.sh <rule-id>
#
# cases.tsv 형식 (탭 구분): <rule-id> <kind> <expect> <param>
#   kind   : path | header | ctbody | raw
#   expect : 403 | 0(코드 미검사)
#   param  : kind 에 맞는 값
#     path   : /?x=...  (base URL 뒤에 붙음)
#     header : "Proxy: 1" 등 curl -H 인자
#     ctbody : "ContentType;body"
#     raw    : printf %b 형식 요청 문자열
#
set -uo pipefail
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HARNESS_DIR/lib.sh"

mapfile -t ALL_IDS < "$HARNESS_DIR/ids.txt"
U="http://127.0.0.1:$PORT"

declare -A CASE_KIND CASE_EXPECT CASE_PARAM
while IFS=$'\t' read -r id kind expect param; do
    [ -z "${id:-}" ] && continue
    [[ "$id" =~ ^# ]] && continue
    CASE_KIND["$id"]="$kind"; CASE_EXPECT["$id"]="$expect"; CASE_PARAM["$id"]="$param"
done < "$HARNESS_DIR/cases.tsv"

run_case() {
    local id="$1" kind="${CASE_KIND[$1]}" expect="${CASE_EXPECT[$1]}" param="${CASE_PARAM[$1]}" code=""
    info "공격 예제($kind): $param"
    case "$kind" in
        path)   code="$(curl_code "$U$param")" ;;
        header) code="$(curl_code -H "$param" "$U/")" ;;
        ctbody) local ct="${param%%;*}" body="${param#*;}"
                code="$(curl_code -H "Content-Type: $ct" --data "$body" "$U/")" ;;
        multipart) code="$(mp_code "$param")" ;;
        raw)    code="$(raw_code "$param")" ;;
        *)      fail "$id: 알 수 없는 kind '$kind'"; return ;;
    esac
    if [ "$expect" != "0" ]; then
        assert_eq "$id → HTTP $expect" "$expect" "$code"
    fi
    assert_fired "$id" "$id 매칭"
}

dispatch() {
    local id="$1"
    if [ -n "${CASE_KIND[$id]:-}" ]; then
        run_case "$id"
    else
        skip "$id: 공격 예제 미구현 (nginx 도달 불가/조건 필요 또는 helper 룰)"
    fi
}

run_one() {
    local id="$1"
    CURRENT_LOG="$TEST_LOG_DIR/$id.log"
    {
        printf '# rule %s\n' "$id"
        printf '# date %s\n' "$(date '+%F %T')"
        printf '# file %s\n\n' "$CONF_NAME"
    } > "$CURRENT_LOG"
    printf '\n[%s] %s\n' "$id" "$CONF_NAME"
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
