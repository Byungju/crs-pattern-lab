#!/usr/bin/env bash
#
# run-all.sh - REQUEST-901-INITIALIZATION.conf 전체 검증 실행
#
# 개별 룰 검증: ./<rule-id>.sh   (예: ./901120.sh)
# 로그: ../../../logs/local_test/REQUEST-901-INITIALIZATION/
#   run-all.log, <rule-id>.log, nginx-error.log, nginx-audit.log ...
#
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$(cd "$DIR/../../.." && pwd)/logs/local_test/REQUEST-901-INITIALIZATION"
mkdir -p "$LOG_DIR"

"$DIR/verify.sh" all 2>&1 | tee "$LOG_DIR/run-all.log"
exit "${PIPESTATUS[0]}"
