#!/usr/bin/env bash
# scripts/run_afl.sh - Multi-Core AFL++ Fuzzing Campaign Launcher
set -euo pipefail

TARGET_HARNESS=${1:-"fuzz_gguf"}
SEEDS_DIR=${2:-"seeds/gguf"}
OUTPUT_DIR=${3:-"out"}
CORES=${4:-4}

echo "[SENTINEL-AFL] Launching AFL++ Fuzzing Campaign..."
echo "[SENTINEL-AFL] Target: ${TARGET_HARNESS} | Seeds: ${SEEDS_DIR} | Cores: ${CORES}"

# Check for afl-fuzz
if ! command -v afl-fuzz &> /dev/null; then
    echo "[CRITICAL] afl-fuzz command not found. Please install AFL++."
    exit 1
fi

# Configure CPU frequency settings for AFL++
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

mkdir -p "${OUTPUT_DIR}"

# Launch Main Master Instance
echo "[SENTINEL-AFL] Starting Master Instance (main)..."
afl-fuzz -i "${SEEDS_DIR}" -o "${OUTPUT_DIR}" -M main -- "./bin/${TARGET_HARNESS}" @@ &

# Launch Secondary Slave Instances
for ((i=1; i<CORES; i++)); do
    echo "[SENTINEL-AFL] Starting Secondary Instance (slave_${i})..."
    afl-fuzz -i "${SEEDS_DIR}" -o "${OUTPUT_DIR}" -S "slave_${i}" -- "./bin/${TARGET_HARNESS}" @@ &
done

echo "[SENTINEL-AFL] All ${CORES} AFL++ instances launched successfully."
echo "[SENTINEL-AFL] Monitor status with: afl-whatsup ${OUTPUT_DIR}"
wait