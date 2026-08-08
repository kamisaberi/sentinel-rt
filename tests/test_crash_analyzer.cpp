/**
 * @file test_crash_analyzer.cpp
 * @brief Unit Tests for Crash Analyzer in sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/triage/crash_analyzer.hpp>
#include <cassert>
#include <iostream>

void test_asan_log_classification() {
    std::string_view sample_asan_log = R"(
=================================================================
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x000000401234
READ of size 4 at 0x602000000010 thread T0
    #0 0x401234 in sentinel::parsers::GGUFParser::parse /workspace/src/parsers/gguf_parser.cpp:45
=================================================================
)";

    sentinel::triage::CrashAnalyzer analyzer;
    auto report = analyzer.analyze_sanitizer_log(sample_asan_log);

    assert(report.cwe_type == sentinel::triage::CWEType::CWE_416_Use_After_Free);
    assert(report.severity == sentinel::triage::CrashSeverity::Critical);
    assert(report.fault_address == 0x602000000010);

    std::cout << "[PASS] test_asan_log_classification\n";
}

int main() {
    std::cout << "[SENTINEL-TEST] Running Crash Analyzer Unit Tests...\n";
    test_asan_log_classification();
    std::cout << "[SENTINEL-TEST] All Crash Analyzer Tests PASSED!\n";
    return 0;
}