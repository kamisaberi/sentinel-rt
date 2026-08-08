#!/usr/bin/env bash
# scripts/run_libfuzzer.sh - LibFuzzer Execution Runner
set -euo pipefail

HARNESS=${1:-"fuzz_gguf"}
SEEDS=${2:-"seeds/gguf"}
WORKERS=${3:-4}
JOBS=${4:-4}

echo "[SENTINEL-LIBFUZZER] Executing LibFuzzer Target: ${HARNESS}"

if [ ! -f "./bin/${HARNESS}" ]; then
    echo "[CRITICAL] Executable ./bin/${HARNESS} not found. Run 'ninja' in build directory first."
    exit 1
fi

mkdir -p ./out/crashes

# Run LibFuzzer harness with AddressSanitizer options
ASAN_OPTIONS="symbolize=1:detect_leaks=0:abort_on_error=1" \
./bin/"${HARNESS}" "${SEEDS}" \
    -artifact_prefix=./out/crashes/ \
    -max_len=1048576 \
    -rss_limit_mb=4096 \
    -workers="${WORKERS}" \
    -jobs="${JOBS}"