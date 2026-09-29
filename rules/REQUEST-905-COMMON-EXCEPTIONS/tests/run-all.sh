#!/usr/bin/env bash
#
# run-all.sh - REQUEST-905-COMMON-EXCEPTIONS.conf 전체 검증 실행
#
# 로그: ../../../logs/local_test/REQUEST-905-COMMON-EXCEPTIONS/
#
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$(cd "$DIR/../../.." && pwd)/logs/local_test/REQUEST-905-COMMON-EXCEPTIONS"
mkdir -p "$LOG_DIR"

"$DIR/verify.sh" all 2>&1 | tee "$LOG_DIR/run-all.log"
exit "${PIPESTATUS[0]}"
