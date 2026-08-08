/**
 * @file crash_analyzer.cpp
 * @brief Crash Triage, Stack Unwinding, and CWE Classification Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/triage/crash_analyzer.hpp>

#include <execinfo.h>
#include <signal.h>
#include <cxxabi.h>
#include <dlfcn.h>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <format>
#include <regex>
#include <cstring>
#include <memory>

namespace sentinel::triage {

namespace {

// Helper to demangle C++ function names
std::string demangle(const char* mangled_name) {
    if (!mangled_name) return "unknown";
    int status = -1;
    std::unique_ptr<char, void(*)(void*)> res{
        abi::__cxa_demangle(mangled_name, nullptr, nullptr, &status),
        std::free
    };
    return (status == 0 && res) ? std::string(res.get()) : std::string(mangled_name);
}

// Helper to convert signal numbers to string names
std::string get_signal_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV (Segmentation Fault)";
        case SIGBUS:  return "SIGBUS (Bus Error / Invalid Alignment)";
        case SIGFPE:  return "SIGFPE (Floating Point Exception / Division by Zero)";
        case SIGABRT: return "SIGABRT (Abort Signal / Assertion Failure)";
        case SIGILL:  return "SIGILL (Illegal Instruction)";
        default:      return std::format("Signal {}", sig);
    }
}

} // anonymous namespace

CrashAnalysisReport CrashAnalyzer::analyze_signal(int signal_number, void* siginfo_ptr, void* /* ucontext_ptr */) {
    CrashAnalysisReport report{};
    report.signal_number = signal_number;
    report.signal_name = get_signal_name(signal_number);
    report.timestamp = std::chrono::system_clock::now();

    if (siginfo_ptr != nullptr) {
        auto* info = static_cast<siginfo_t*>(siginfo_ptr);
        report.fault_address = reinterpret_cast<uintptr_t>(info->si_addr);
    }

    report.stack_trace = capture_stack_trace(32);
    report.cwe_type = classify_cwe(Status::ErrSanitizerViolation, signal_number, report.signal_name);
    report.severity = evaluate_severity(report.cwe_type, report.fault_address);

    auto time_secs = std::chrono::duration_cast<std::chrono::seconds>(report.timestamp.time_since_epoch()).count();
    report.crash_id = std::format("CRASH-SIG{}-0x{:x}-{}", signal_number, report.fault_address, time_secs);

    report.summary = std::format("{} detected at address 0x{:x}. Classified as {} [Severity: {}]",
        report.signal_name,
        report.fault_address,
        cwe_to_string(report.cwe_type),
        static_cast<uint32_t>(report.severity)
    );

    return report;
}

CrashAnalysisReport CrashAnalyzer::analyze_sanitizer_log(std::string_view sanitizer_log) {
    CrashAnalysisReport report{};
    report.timestamp = std::chrono::system_clock::now();
    std::string log_str(sanitizer_log);

    // Regex to extract fault address from AddressSanitizer logs
    std::regex addr_regex(R"(0x[0-9a-fa-f]+)");
    std::smatch match;
    if (std::regex_search(log_str, match, addr_regex)) {
        report.fault_address = std::stoull(match.str(), nullptr, 16);
    }

    report.cwe_type = classify_cwe(Status::ErrSanitizerViolation, 0, sanitizer_log);
    report.severity = evaluate_severity(report.cwe_type, report.fault_address);

    auto time_secs = std::chrono::duration_cast<std::chrono::seconds>(report.timestamp.time_since_epoch()).count();
    report.crash_id = std::format("CRASH-ASAN-0x{:x}-{}", report.fault_address, time_secs);

    report.summary = std::format("Sanitizer Violation: {} at fault address 0x{:x}.",
        cwe_to_string(report.cwe_type),
        report.fault_address
    );

    return report;
}

std::vector<StackFrame> CrashAnalyzer::capture_stack_trace(size_t max_depth) {
    std::vector<StackFrame> frames;
    std::vector<void*> buffer(max_depth);

    int num_frames = backtrace(buffer.data(), static_cast<int>(max_depth));
    char** symbols = backtrace_symbols(buffer.data(), num_frames);

    if (!symbols) {
        return frames;
    }

    frames.reserve(static_cast<size_t>(num_frames));

    for (int i = 0; i < num_frames; ++i) {
        StackFrame frame{};
        frame.frame_index = static_cast<uint32_t>(i);
        frame.instruction_address = reinterpret_cast<uintptr_t>(buffer[static_cast<size_t>(i)]);

        Dl_info dlinfo;
        if (dladdr(buffer[static_cast<size_t>(i)], &dlinfo) && dlinfo.dli_sname) {
            frame.function_name = demangle(dlinfo.dli_sname);
            frame.module_name = dlinfo.dli_fname ? dlinfo.dli_fname : "unknown";
        } else if (symbols[i]) {
            frame.function_name = symbols[i];
        }

        frames.push_back(std::move(frame));
    }

    free(symbols);
    return frames;
}

CWEType CrashAnalyzer::classify_cwe(Status status, int signal_number, std::string_view log_snippet) noexcept {
    std::string log(log_snippet);

    if (log.find("heap-use-after-free") != std::string::npos || log.find("use-after-free") != std::string::npos) {
        return CWEType::CWE_416_Use_After_Free;
    }
    if (log.find("heap-buffer-overflow") != std::string::npos || log.find("global-buffer-overflow") != std::string::npos) {
        return CWEType::CWE_122_Heap_Overflow;
    }
    if (log.find("stack-buffer-overflow") != std::string::npos || status == Status::ErrOutOfBoundsRead) {
        return CWEType::CWE_119_Memory_Bounds;
    }
    if (log.find("integer-overflow") != std::string::npos || status == Status::ErrIntegerOverflow) {
        return CWEType::CWE_190_Integer_Overflow;
    }
    if (log.find("null-pointer") != std::string::npos || signal_number == SIGSEGV) {
        return CWEType::CWE_476_Null_Pointer;
    }

    return CWEType::CWE_Unknown;
}

CrashSeverity CrashAnalyzer::evaluate_severity(CWEType cwe, uintptr_t fault_addr) noexcept {
    // Null pointer dereferences at address 0x0 are typically lower severity (DoS rather than RCE)
    if (cwe == CWEType::CWE_476_Null_Pointer || fault_addr < 0x1000) {
        return CrashSeverity::Low;
    }

    switch (cwe) {
        case CWEType::CWE_122_Heap_Overflow:
        case CWEType::CWE_416_Use_After_Free:
            return CrashSeverity::Critical; // High exploitability potential
        case CWEType::CWE_119_Memory_Bounds:
        case CWEType::CWE_190_Integer_Overflow:
            return CrashSeverity::High;
        default:
            return CrashSeverity::Medium;
    }
}

Status CrashAnalyzer::export_json(const CrashAnalysisReport& report, const std::filesystem::path& output_path) {
    std::ofstream out(output_path);
    if (!out.is_open()) {
        return Status::ErrOutOfBoundsRead;
    }

    out << "{\n"
        << "  \"crash_id\": \"" << report.crash_id << "\",\n"
        << "  \"cwe_type\": \"" << cwe_to_string(report.cwe_type) << "\",\n"
        << "  \"severity\": " << static_cast<uint32_t>(report.severity) << ",\n"
        << "  \"signal_number\": " << report.signal_number << ",\n"
        << "  \"signal_name\": \"" << report.signal_name << "\",\n"
        << "  \"fault_address\": \"0x" << std::hex << report.fault_address << std::dec << "\",\n"
        << "  \"summary\": \"" << report.summary << "\",\n"
        << "  \"stack_trace\": [\n";

    for (size_t i = 0; i < report.stack_trace.size(); ++i) {
        const auto& frame = report.stack_trace[i];
        out << "    {\n"
            << "      \"frame\": " << frame.frame_index << ",\n"
            << "      \"address\": \"0x" << std::hex << frame.instruction_address << std::dec << "\",\n"
            << "      \"function\": \"" << frame.function_name << "\",\n"
            << "      \"module\": \"" << frame.module_name << "\"\n"
            << "    }" << (i + 1 < report.stack_trace.size() ? "," : "") << "\n";
    }

    out << "  ]\n}\n";
    return Status::Success;
}

} // namespace sentinel::triage