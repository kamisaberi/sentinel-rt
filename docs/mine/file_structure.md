
```
sentinel-rt/
├── README.md                          # Production-grade overview, threat model, & benchmarks
├── LICENSE                            # Apache 2.0 / MIT License
├── CMakeLists.txt                     # Main CMake build script (Sanitizers + CUDA + AFL++)
├── Dockerfile                         # Hermetic fuzzing environment (Clang 18, AFL++, ASan)
├── .clang-format                      # LLVM/C++20 coding style guide
├── .gitignore                         # Ignores fuzzing artifacts, crash dumps, build/
│
├── cmake/                             # CMake Modules & Compiler Flags
│   ├── FindAFL.cmake                  # Detects AFL++ compiler wrappers (afl-clang-lto++)
│   ├── Sanitizers.cmake               # Enables ASan, UBSan, TSan, & MSan flags
│   └── CUDAUtils.cmake                # CUDA architecture flags & compute sanitizer hooks
│
├── include/sentinel/                  # Public C++ Headers
│   ├── sentinel.hpp                   # Core library entry point
│   │
│   ├── fuzzer/                        # Fuzzing Engine & Coverage Drivers
│   │   ├── fuzz_engine.hpp            # Generic fuzzer wrapper interface
│   │   ├── coverage_tracker.hpp       # Real-time C++ code coverage tracker
│   │   └── mutator_interface.hpp      # Custom structure-aware mutator base class
│   │
│   ├── parsers/                       # Native Format Parsers (Targets under audit)
│   │   ├── gguf_parser.hpp            # Safe GGUF model header/tensor parser
│   │   ├── safetensors_parser.hpp     # Fast C++ Safetensors parser
│   │   └── onnx_parser.hpp            # ONNX protobuf/flatbuffer inspector
│   │
│   ├── sanitizers/                    # Memory Safety & CUDA Allocator Checks
│   │   ├── asan_hooks.hpp             # Manual ASan poisoning hooks for custom allocators
│   │   ├── cuda_sanitizer.hpp         # CUDA VRAM dynamic bounds & race condition checker
│   │   └── arena_checker.hpp          # Custom C++ memory pool boundary auditor
│   │
│   ├── triage/                        # Crash Triage & Root Cause Analysis
│   │   ├── crash_analyzer.hpp         # Crash dump analyzer (UAF, OOB, Buffer Overflow)
│   │   ├── stack_trace.hpp            # Symbolized stack trace capture (libunwind)
│   │   └── cve_classifier.hpp         # Vulnerability classification (CWE-119, CWE-416)
│   │
│   └── adapters/                      # Target AI Engine Adapters
│       ├── llamacpp_adapter.hpp       # Hooks for llama.cpp runtime execution
│       ├── vllm_adapter.hpp           # Native C++ hooks for vLLM backends
│       └── libtorch_adapter.hpp       # LibTorch tensor allocation hooks
│
├── src/                               # C++ Implementation Files
│   ├── fuzzer/
│   │   ├── fuzz_engine.cpp
│   │   └── coverage_tracker.cpp
│   ├── parsers/
│   │   ├── gguf_parser.cpp
│   │   ├── safetensors_parser.cpp
│   │   └── onnx_parser.cpp
│   ├── sanitizers/
│   │   ├── asan_hooks.cpp
│   │   └── cuda_sanitizer.cpp
│   ├── triage/
│   │   ├── crash_analyzer.cpp
│   │   └── cve_classifier.cpp
│   └── adapters/
│       ├── llamacpp_adapter.cpp
│       └── libtorch_adapter.cpp
│
├── harnesses/                         # Fuzzing Entrypoints (Target Targets)
│   ├── fuzz_gguf.cpp                  # LibFuzzer entrypoint for GGUF deserialization
│   ├── fuzz_safetensors.cpp           # LibFuzzer entrypoint for Safetensors header parsing
│   ├── fuzz_onnx.cpp                  # LibFuzzer entrypoint for ONNX graph parsers
│   └── fuzz_cuda_alloc.cpp            # Fuzzing harness for CUDA VRAM allocator hooks
│
├── mutators/                          # AFL++ Custom Mutators (Shared Libraries)
│   ├── gguf_mutator.cpp               # Structure-aware GGUF custom AFL++ mutator
│   └── safetensors_mutator.cpp        # Structure-aware Safetensors AFL++ mutator
│
├── seeds/                             # Initial Corpus Seeds for Fuzzing
│   ├── gguf/                          # Valid & malformed minimal GGUF model files
│   ├── safetensors/                   # Minimal valid JSON + binary tensor files
│   └── onnx/                          # Minimal valid ONNX graph protobufs
│
├── scripts/                           # Automation & Crash Triage Tooling
│   ├── run_afl.sh                     # Launch multi-core AFL++ fuzzing campaign
│   ├── run_libfuzzer.sh               # Run LibFuzzer with ASan enabled
│   ├── triage_crashes.py              # Auto-deduplicate crash dumps using GDB/LLDB
│   └── minify_corpus.sh               # Corpus minimization script (afl-cmin / afl-tmin)
│
└── tests/                             # Unit & Integration Tests
    ├── CMakeLists.txt
    ├── test_gguf_parser.cpp           # Unit test for valid GGUF parsing
    ├── test_cuda_sanitizer.cpp        # Test CUDA memory bounds checker
    └── test_crash_analyzer.cpp        # Test crash classification logic

    ```