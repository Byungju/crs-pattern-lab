#!/usr/bin/env bash
#
# run-all.sh - REQUEST-922-MULTIPART-ATTACK.conf 전체 검증 실행
#
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$(cd "$DIR/../../.." && pwd)/logs/local_test/REQUEST-922-MULTIPART-ATTACK"
mkdir -p "$LOG_DIR"
"$DIR/verify.sh" all 2>&1 | tee "$LOG_DIR/run-all.log"
exit "${PIPESTATUS[0]}"
