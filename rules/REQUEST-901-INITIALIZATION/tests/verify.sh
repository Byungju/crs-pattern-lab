#!/usr/bin/env bash
#
# verify.sh - REQUEST-901-INITIALIZATION.conf 룰 검증
#
# 사용법:
#   ./verify.sh all          # 모든 룰 검증
#   ./verify.sh 901120 901001
#
# 901 룰은 대부분 공격 탐지가 아니라 "초기화" 룰이므로, 실제 공격 payload 대신
#   - nolog 변수 룰 : 테스트용 probe 룰(9900001)로 TX 변수 값을 확인
#   - 로그 룰       : 별도 설정 인스턴스로 응답 코드/감지 로그 확인
# 방식으로 검증한다.
#
set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HARNESS_DIR/lib.sh"

ALL_IDS=(
    901001 901100 901110 901111 901115 901120 901125 901130
    901140 901141 901142 901143 901160 901162 901163 901164
    901165 901167 901168 901169 901170 901171 901200 901320
    901340 901350 901400 901410 901450 901500 901510
)

# 룰 id -> "probe_key#기대값"  (정확히 일치 비교)
declare -A VARCASE=(
    [901100]="inbound_thr#5"
    [901110]="outbound_thr#4"
    [901111]="reporting#4"
    [901115]="early#0"
    [901120]="blocking_pl#1"
    [901125]="detection_pl#1"
    [901130]="sampling#100"
    [901140]="crit#5"
    [901141]="error#4"
    [901142]="warning#3"
    [901143]="notice#2"
    [901160]="allowed_methods#GET HEAD POST OPTIONS"
    [901162]="allowed_ct#|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json|"
    [901163]="allowed_http#HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0"
    [901167]="enforce_urlenc#0"
    [901168]="allowed_charset#|utf-8| |iso-8859-1| |iso-8859-15| |windows-1252|"
    [901169]="utf8#1"
    [901170]="skip_resp#0"
    [901171]="restricted_hdr_ext#/accept-charset/"
    [901510]="method_override#0"
)

# 룰 id -> "probe_key#부분 문자열"  (긴 목록은 포함 여부만 확인)
declare -A VARCASE_CONTAINS=(
    [901164]="restricted_ext#.bak/ .bck/ .bk/ .bkp/"
    [901165]="restricted_hdr_basic#/x-middleware-subrequest/ /expect/"
)

# ---------------------------------------------------------------------------
# 개별 케이스 처리
# ---------------------------------------------------------------------------
case_901001() {
    info "crs-setup.conf 없이 CRS rules 만 로드 → 901001 이 500 차단해야 함"
    gen_nosetup_conf
    : > "$TEST_LOG_DIR/nginx-nosetup-error.log"
    start_nginx "$CONF_DIR/crs-test-nginx-nosetup.conf"
    assert_code "$VARIANT_PORT_1" "/" 500 "901001: setup 누락 감지 차단"
    assert_log_has "$TEST_LOG_DIR/nginx-nosetup-error.log" 'id "901001"' \
        "901001: error log 에 감지 메시지 기록"
    stop_nginx "$CONF_DIR/crs-test-nginx-nosetup.conf"
}

case_901200() {
    info "어노말리 스코어 변수를 0 으로 초기화하는지 확인"
    probe_request
    assert_probe "score_in" "0" "룰 901200: blocking_inbound_anomaly_score 초기화"
    assert_probe "score_det_in" "0" "룰 901200: detection_inbound_anomaly_score 초기화"
    assert_probe "score_out" "0" "룰 901200: blocking_outbound_anomaly_score 초기화"
    assert_probe "sql" "0" "룰 901200: sql_injection_score 초기화"
}

case_901340() {
    info "901340 은 nolog/noauditlog 룰이므로 디버그 로그(level 9)로 평가 여부 확인"
    gen_debug_conf "901340" "$VARIANT_PORT_1"
    : > "$TEST_LOG_DIR/nginx-901340-debug.log"
    start_nginx "$CONF_DIR/crs-test-nginx-901340.conf"
    curl -s -o /dev/null -m 5 -X POST -H 'Host: localhost' \
        -H 'Content-Type: text/plain' --data 'crs901340=probe' \
        "http://127.0.0.1:$VARIANT_PORT_1/" 2>/dev/null
    sleep 0.3
    assert_log_has "$TEST_LOG_DIR/nginx-901340-debug.log" '(Rule: 901340)' \
        "901340: REQBODY_PROCESSOR 대상 룰 평가 확인 (debug)"
    stop_nginx "$CONF_DIR/crs-test-nginx-901340.conf"
}

case_901400() {
    info "sampling_percentage=100 이면 901400 이 skipAfter 로 샘플링 블록을 건너뛴다"
    probe_request
    assert_probe "sampling_rnd100" "" "901400: 샘플링 난수(901410) 미계산(블록 skip)"
}

case_901320() {
    skip "901320: ENABLE_DEFAULT_COLLECTIONS 컬렉션 초기화는 기본 비활성(tx.enable_default_collections=0)"
}
case_901350() {
    skip "901350: body processor 강제는 tx.enforce_bodyproc_urlencoded=0 이라 기본 비활성(900010 활성화 필요)"
}
case_901410() {
    skip "901410: sampling=100 이면 901400 이 skip 하므로 기본 미실행"
}
case_901450() {
    skip "901450: sampling=100 이면 샘플링 제외 룰이 실행되지 않음(샘플링 활성화 시 검증)"
}

case_901500() {
    info "detection_pl(1) < blocking_pl(2) 강제 → 901500 이 500 차단해야 함"
    gen_invalidpl_conf
    : > "$TEST_LOG_DIR/nginx-invalidpl-error.log"
    start_nginx "$CONF_DIR/crs-test-nginx-invalidpl.conf"
    assert_code "$VARIANT_PORT_2" "/" 500 "901500: PL 설정 오류 감지 차단"
    assert_log_has "$TEST_LOG_DIR/nginx-invalidpl-error.log" 'id "901500"' \
        "901500: error log 에 감지 메시지 기록"
    stop_nginx "$CONF_DIR/crs-test-nginx-invalidpl.conf"
}

# ---------------------------------------------------------------------------
dispatch() {
    local id="$1"
    case "$id" in
        901001) case_901001 ;;
        901200) case_901200 ;;
        901340) case_901340 ;;
        901400) case_901400 ;;
        901320|901350|901410|901450) "case_$id" ;;
        901500) case_901500 ;;
        *)
            if [ -n "${VARCASE[$id]:-}" ]; then
                local key exp
                IFS='#' read -r key exp <<< "${VARCASE[$id]}"
                info "룰 $id: $key == '$exp' (probe 확인)"
                probe_request
                assert_probe "$key" "$exp" "룰 $id: $key 초기화"
            elif [ -n "${VARCASE_CONTAINS[$id]:-}" ]; then
                local key sub
                IFS='#' read -r key sub <<< "${VARCASE_CONTAINS[$id]}"
                info "룰 $id: $key 에 '$sub' 포함 확인"
                probe_request
                assert_probe_contains "$key" "$sub" "룰 $id: $key 초기화"
            else
                fail "알 수 없는 룰 id: $id"
            fi
            ;;
    esac
}

run_one() {
    local id="$1"
    CURRENT_LOG="$TEST_LOG_DIR/$id.log"
    {
        printf '# rule %s\n' "$id"
        printf '# date %s\n' "$(date '+%F %T')"
        printf '# file REQUEST-901-INITIALIZATION.conf\n\n'
    } > "$CURRENT_LOG"
    printf '\n[%s] %s\n' "$id" "REQUEST-901-INITIALIZATION.conf"
    dispatch "$id"
    CURRENT_LOG=""
}

main() {
    mkdir -p "$TEST_LOG_DIR"
    [ -x "$NGINX" ] || { echo "nginx 없음: $NGINX (먼저 build.sh 실행)"; exit 1; }
    [ -f "$CONF_DIR/modsecurity.conf" ] || { echo "modsecurity.conf 없음 (setup-config.sh 실행)"; exit 1; }

    local targets=("$@")
    [ ${#targets[@]} -eq 0 ] && targets=("all")
    if [ "${targets[0]}" = "all" ]; then
        targets=("${ALL_IDS[@]}")
    fi

    gen_main_conf
    main_start

    local id
    for id in "${targets[@]}"; do
        run_one "$id"
    done

    test_case_stop
    cleanup_artifacts

    printf '\n%s\n' "----------------------------------------"
    printf 'PASS=%d  FAIL=%d  SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
    [ "$FAIL" -eq 0 ]
}

main "$@"
