#!/usr/bin/env python3
"""
scripts/triage_crashes.py
Automated Crash Triaging, Stack Symbolization, and CWE Deduplication for sentinel-rt

Author: Kamran Saberifard
License: Apache 2.0

Usage:
  python3 scripts/triage_crashes.py \
    --target ./bin/fuzz_gguf \
    --crashes ./out/crashes/ \
    --output ./reports/summary.json
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class CrashReport:
    crash_file: str
    crash_hash: str
    cwe_type: str
    severity: str
    fault_address: str
    asan_report_type: str
    stack_top: List[str] = field(default_factory=list)
    raw_log: str = ""


class CrashTriager:
    def __init__(self, target_binary: Path, crash_dir: Path, timeout: float = 5.0):
        self.target_binary = target_binary.resolve()
        self.crash_dir = crash_dir.resolve()
        self.timeout = timeout

        if not self.target_binary.exists() or not os.access(self.target_binary, os.X_OK):
            raise FileNotFoundError(f"Target binary not found or not executable: {self.target_binary}")

        if not self.crash_dir.exists():
            raise FileNotFoundError(f"Crash directory not found: {self.crash_dir}")

    def run_target(self, crash_file: Path) -> subprocess.CompletedProcess:
        """Executes the target binary with a crash seed file."""
        cmd = [str(self.target_binary), str(crash_file)]
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "symbolize=1:detect_leaks=0:abort_on_error=1"
        env["UBSAN_OPTIONS"] = "print_stacktrace=1"

        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=-1,
                stdout="",
                stderr="[SENTINEL-TRIAGE] Execution Timed Out (Possible Hang / Infinite Loop)",
            )

    def parse_asan_log(self, crash_file: Path, stderr: str) -> CrashReport:
        """Parses AddressSanitizer and UBSan error reports from stderr."""
        report_type = "Unknown-Crash"
        cwe_type = "CWE-999: Unclassified"
        severity = "Medium"
        fault_addr = "0x0"
        stack_frames: List[str] = []

        # Extract ASan Error Type
        asan_match = re.search(r"ERROR: AddressSanitizer:\s*([a-zA-Z\-]+)", stderr)
        if asan_match:
            report_type = asan_match.group(1)

        # Extract Fault Address
        addr_match = re.search(r"0x[0-9a-fA-F]+", stderr)
        if addr_match:
            fault_addr = addr_match.group(0)

        # Extract Stack Frames (#0, #1, #2)
        frame_matches = re.findall(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+([^\n]+)", stderr)
        if frame_matches:
            stack_frames = [f.strip() for f in frame_matches[:5]]

        # Classify CWE and Severity based on ASan report type
        if "use-after-free" in report_type.lower():
            cwe_type = "CWE-416: Use-After-Free"
            severity = "Critical"
        elif "heap-buffer-overflow" in report_type.lower():
            cwe_type = "CWE-122: Heap-Based Buffer Overflow"
            severity = "Critical"
        elif "stack-buffer-overflow" in report_type.lower() or "global-buffer-overflow" in report_type.lower():
            cwe_type = "CWE-119: Memory Bounds Violation"
            severity = "High"
        elif "null-pointer" in stderr.lower() or fault_addr == "0x0":
            cwe_type = "CWE-476: NULL Pointer Dereference"
            severity = "Low"
        elif "integer-overflow" in stderr.lower():
            cwe_type = "CWE-190: Integer Overflow"
            severity = "High"

        # Compute unique crash hash from stack top to deduplicate
        stack_signature = "|".join(stack_frames) if stack_frames else stderr[:200]
        crash_hash = hashlib.sha256(stack_signature.encode("utf-8")).hexdigest()[:16]

        return CrashReport(
            crash_file=crash_file.name,
            crash_hash=crash_hash,
            cwe_type=cwe_type,
            severity=severity,
            fault_address=fault_addr,
            asan_report_type=report_type,
            stack_top=stack_frames,
            raw_log=stderr[:1000],  # Truncate raw log snippet
        )

    def triage_all(self, max_workers: int = 8) -> Dict:
        """Processes all crash files in parallel and deduplicates reports."""
        crash_files = [f for f in self.crash_dir.iterdir() if f.is_file() and not f.name.startswith(".")]

        print(f"[SENTINEL-TRIAGE] Found {len(crash_files)} crash files in {self.crash_dir}")
        print(f"[SENTINEL-TRIAGE] Target Binary: {self.target_binary}")
        print(f"[SENTINEL-TRIAGE] Triaging crashes across {max_workers} parallel workers...")

        unique_crashes: Dict[str, Dict] = {}
        total_processed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(self.run_target, f): f for f in crash_files}

            for future in concurrent.futures.as_completed(future_to_file):
                crash_file = future_to_file[future]
                total_processed += 1

                try:
                    proc = future.result()
                    log = proc.stderr if proc.stderr else proc.stdout
                    report = self.parse_asan_log(crash_file, log)

                    if report.crash_hash not in unique_crashes:
                        unique_crashes[report.crash_hash] = {
                            "dedup_hash": report.crash_hash,
                            "cwe_type": report.cwe_type,
                            "severity": report.severity,
                            "report_type": report.asan_report_type,
                            "fault_address": report.fault_address,
                            "stack_top": report.stack_top,
                            "representative_file": report.crash_file,
                            "matching_crash_count": 1,
                            "sample_log": report.raw_log[:400],
                        }
                    else:
                        unique_crashes[report.crash_hash]["matching_crash_count"] += 1

                except Exception as e:
                    print(f"[ERROR] Failed to triage {crash_file.name}: {e}", file=sys.stderr)

        summary_report = {
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target_binary": str(self.target_binary.name),
                "total_crash_files_triaged": total_processed,
                "unique_crash_signatures": len(unique_crashes),
            },
            "unique_vulnerabilities": list(unique_crashes.values()),
        }

        return summary_report


def main():
    parser = argparse.ArgumentParser(description="sentinel-rt Automated Crash Triaging & Deduplication Utility")
    parser.add_argument("--target", required=True, type=Path, help="Path to compiled target binary (e.g., ./bin/fuzz_gguf)")
    parser.add_argument("--crashes", required=True, type=Path, help="Directory containing crash input files")
    parser.add_argument("--output", default=Path("reports/summary.json"), type=Path, help="Path to write JSON summary report")
    parser.add_argument("--workers", default=8, type=int, help="Number of parallel triage workers")

    args = parser.parse_args()

    try:
        triager = CrashTriager(args.target, args.crashes)
        summary = triager.triage_all(max_workers=args.workers)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"\n[SENTINEL-TRIAGE] Triage Complete!")
        print(f"[SENTINEL-TRIAGE] Total Crash Files: {summary['metadata']['total_crash_files_triaged']}")
        print(f"[SENTINEL-TRIAGE] Unique Vulnerability Signatures: {summary['metadata']['unique_crash_signatures']}")
        print(f"[SENTINEL-TRIAGE] Report Written to: {args.output.resolve()}\n")

    except Exception as err:
        print(f"[CRITICAL ERROR] {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()