#!/usr/bin/env bash
# scripts/minify_corpus.sh - Corpus Minimization Utility
set -euo pipefail

TARGET=${1:-"fuzz_gguf"}
INPUT_SEEDS=${2:-"seeds/gguf"}
OUTPUT_MINIFIED=${3:-"seeds/gguf_minified"}

echo "[SENTINEL-MINIFY] Minimizing Seed Corpus for Target: ${TARGET}"

if ! command -v afl-cmin &> /dev/null; then
    echo "[CRITICAL] afl-cmin tool not found. Install AFL++."
    exit 1
fi

mkdir -p "${OUTPUT_MINIFIED}"

afl-cmin -i "${INPUT_SEEDS}" -o "${OUTPUT_MINIFIED}" -- "./bin/${TARGET}" @@

echo "[SENTINEL-MINIFY] Corpus minimization complete. Output saved to: ${OUTPUT_MINIFIED}"