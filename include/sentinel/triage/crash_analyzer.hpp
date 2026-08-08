/**
 * @file crash_analyzer.hpp
 * @brief Crash Triage, Stack Trace Symbolization, and CWE Classification for sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <sentinel/sentinel.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <chrono>
#include <filesystem>

namespace sentinel::triage {

/**
 * @brief Common Weakness Enumeration (CWE) classification for detected vulnerabilities.
 */
enum class CWEType : uint32_t {
    CWE_119_Memory_Bounds       = 119, // Improper Restriction of Operations within Bounds
    CWE_122_Heap_Overflow      = 122, // Heap-based Buffer Overflow
    CWE_190_Integer_Overflow   = 190, // Integer Overflow or Wraparound
    CWE_416_Use_After_Free     = 416, // Use After Free
    CWE_476_Null_Pointer       = 476, // NULL Pointer Dereference
    CWE_Unknown                = 999  // Unclassified Crash
};

/**
 * @brief Severity rating for triaged crashes based on exploitability heuristics.
 */
enum class CrashSeverity : uint32_t {
    Low      = 0,
    Medium   = 1,
    High     = 2,
    Critical = 3
};

/**
 * @brief Converts a CWEType enum to a standardized string representation (e.g., "CWE-416").
 */
[[nodiscard]] constexpr std::string_view cwe_to_string(CWEType cwe) noexcept {
    switch (cwe) {
        case CWEType::CWE_119_Memory_Bounds:     return "CWE-119: Memory Bounds Violation";
        case CWEType::CWE_122_Heap_Overflow:    return "CWE-122: Heap-Based Buffer Overflow";
        case CWEType::CWE_190_Integer_Overflow: return "CWE-190: Integer Overflow";
        case CWEType::CWE_416_Use_After_Free:   return "CWE-416: Use-After-Free";
        case CWEType::CWE_476_Null_Pointer:     return "CWE-476: NULL Pointer Dereference";
        default:                                return "CWE-999: Unclassified Vulnerability";
    }
}

/**
 * @brief Represents a single frame in a captured stack trace.
 */
struct SENTINEL_API StackFrame {
    uint32_t frame_index{0};
    uintptr_t instruction_address{0};
    std::string function_name{"unknown"};
    std::string source_file{"unknown"};
    uint32_t line_number{0};
    std::string module_name{"unknown"};
};

/**
 * @brief Structure encapsulating a complete deduplicated crash analysis report.
 */
struct SENTINEL_API CrashAnalysisReport {
    std::string crash_id;
    CWEType cwe_type{CWEType::CWE_Unknown};
    CrashSeverity severity{CrashSeverity::Low};
    Status sentinel_status{Status::ErrUnknown};
    uintptr_t fault_address{0};
    std::string signal_name;
    int signal_number{0};
    std::vector<StackFrame> stack_trace;
    std::string register_state;
    std::string summary;
    std::chrono::system_clock::time_point timestamp{std::chrono::system_clock::now()};
};

/**
 * @brief Crash Triage, Stack Symbolizer, and Vulnerability Classifier.
 */
class SENTINEL_API CrashAnalyzer {
public:
    CrashAnalyzer() = default;
    ~CrashAnalyzer() = default;

    /**
     * @brief Analyzes POSIX signal crash context (SIGSEGV, SIGBUS, SIGFPE).
     * 
     * @param signal_number POSIX signal code.
     * @param siginfo_ptr Pointer to POSIX siginfo_t struct (or nullptr).
     * @param ucontext_ptr Pointer to POSIX ucontext_t struct for CPU register state (or nullptr).
     * @return Generated CrashAnalysisReport.
     */
    [[nodiscard]] CrashAnalysisReport analyze_signal(int signal_number, void* siginfo_ptr = nullptr, void* ucontext_ptr = nullptr);

    /**
     * @brief Parses and classifies AddressSanitizer (ASan) or UBSan log output.
     * 
     * @param sanitizer_log Raw text output from ASan/UBSan report.
     * @return Generated CrashAnalysisReport.
     */
    [[nodiscard]] CrashAnalysisReport analyze_sanitizer_log(std::string_view sanitizer_log);

    /**
     * @brief Captures and symbolicates the current thread stack trace up to max_depth.
     * 
     * @param max_depth Maximum number of stack frames to unwind (default: 32).
     * @return Vector of captured StackFrame objects.
     */
    [[nodiscard]] static std::vector<StackFrame> capture_stack_trace(size_t max_depth = 32);

    /**
     * @brief Classifies a crash into a CWE category based on status, signal, and logs.
     */
    [[nodiscard]] static CWEType classify_cwe(Status status, int signal_number, std::string_view log_snippet) noexcept;

    /**
     * @brief Classifies crash severity based on CWE type and fault address characteristics.
     */
    [[nodiscard]] static CrashSeverity evaluate_severity(CWEType cwe, uintptr_t fault_addr) noexcept;

    /**
     * @brief Exports a CrashAnalysisReport to a formatted JSON file.
     * 
     * @param report Report to export.
     * @param output_path Target file path.
     * @return Status::Success if file was successfully written.
     */
    static Status export_json(const CrashAnalysisReport& report, const std::filesystem::path& output_path);
};

} // namespace sentinel::triage