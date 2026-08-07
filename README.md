# sentinel-rt

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![CUDA](https://img.shields.io/badge/CUDA-12.0%2B-green.svg)](https://developer.nvidia.com/cuda-toolkit)
[![Fuzzer](https://img.shields.io/badge/AFL%2B%2B-Supported-red.svg)](https://github.com/AFLplusplus/AFLplusplus)
[![Sanitizer](https://img.shields.io/badge/ASan%2FUBSan-Enabled-brightgreen.svg)](https://clang.llvm.org/docs/AddressSanitizer.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **High-Throughput C++/CUDA Fuzzing Harness & Memory Safety Auditor for Native AI Execution Runtimes.**

`sentinel-rt` is a specialized, native security auditing framework engineered to discover zero-day memory corruption vulnerabilities, buffer overflows, use-after-free (UAF) flaws, and race conditions in modern deep learning runtimes and model deserialization engines.

Designed for high-performance AI infrastructure, `sentinel-rt` provides structure-aware custom mutators, LibFuzzer/AFL++ harnesses, real-time CUDA VRAM dynamic boundary auditors, and automated crash triaging for frameworks like **llama.cpp**, **vLLM**, **LibTorch**, and **ONNX Runtime**.

---

## 🏛️ System Architecture

```
                                  +---------------------------------+
                                  |     Initial Seed Corpus         |
                                  |   (GGUF, Safetensors, ONNX)     |
                                  +---------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|  sentinel-rt Execution Environment                                                                |
|                                                                                                   |
|   +--------------------------+       +----------------------------+       +-------------------+   |
|   | AFL++ / LibFuzzer        | ----> | Custom Structure-Aware     | ----> | Instrumented      |   |
|   | Coverage Driver          |       | Grammar Mutators           |       | Target Harness    |   |
|   +--------------------------+       +----------------------------+       +-------------------+   |
|                                                                                     |             |
|                                                                                     v             |
|   +--------------------------+       +----------------------------+       +-------------------+   |
|   | Crash Triage &           | <---- | ASan / UBSan / CUDA        | <---- | Target AI Engine  |   |
|   | CWE Classifier           |       | Dynamic Boundary Auditor   |       | (llama.cpp/vLLM)  |   |
|   +--------------------------+       +----------------------------+       +-------------------+   |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
                                  +---------------------------------+
                                  |   Deduplicated Crash Report     |
                                  |   (GDB / Stack Trace / CVE PoC) |
                                  +---------------------------------+
```

---

## ✨ Key Features

- **Structure-Aware Grammar Mutators:** Custom AFL++ mutator plugins for complex binary/JSON model formats including **GGUF (v1–v3)**, **Safetensors**, and **ONNX FlatBuffers**.
- **CUDA VRAM Dynamic Boundary Auditor:** Wraps native CUDA memory allocations (`cudaMalloc`, custom caching allocators) to detect dynamic VRAM out-of-bounds writes and race conditions.
- **LLVM Sanitizer Integration:** Built-in hooks for **AddressSanitizer (ASan)**, **UndefinedBehaviorSanitizer (UBSan)**, and **MemorySanitizer (MSan)** for precise, zero-false-positive crash identification.
- **Micro-Harness Execution:** Low-overhead LibFuzzer C++20 entrypoints that fuzz model headers, tensor metadata, and execution graphs in memory without spawning child processes.
- **Automated Crash Triaging:** Built-in Python/GDB triager that automatically deduplicates crash dumps, symbolicates stack traces, and classifies vulnerabilities by CWE (CWE-119, CWE-416, CWE-190).

---

## 🎯 Supported Target Formats & Runtimes

| Target / Format | Audit Module | Attack Surface Covered |
| :--- | :--- | :--- |
| **GGUF (v1-v3)** | `sentinel::parsers::GGUFParser` | Header metadata parsing, tensor dimension arithmetic, string buffer handling. |
| **Safetensors** | `sentinel::parsers::SafetensorsParser` | JSON header parsing, offset calculation, zero-copy buffer boundaries. |
| **ONNX Runtime** | `sentinel::parsers::ONNXParser` | Graph protobuf deserialization, node attribute parsing, shape inference. |
| **llama.cpp** | `sentinel::adapters::LlamaCppAdapter` | Native C++ context allocation, tokenization loops, quantization decoding. |
| **LibTorch / PyTorch** | `sentinel::adapters::LibTorchAdapter` | C++ tensor allocation, CUDA caching allocator hooks, operator execution. |

---

## 🛠️ Quick Start

### Prerequisites

- **OS:** Linux (Ubuntu 22.04 LTS / 24.04 LTS recommended)
- **Compiler:** Clang 18+ (with `-fsanitize=fuzzer,address,undefined` support)
- **CUDA Toolkit:** CUDA 12.0+
- **Build System:** CMake 3.20+, Ninja, Make
- **Tools:** AFL++ (`afl-clang-lto++`), GDB, Python 3.10+

### Option 1: Building with Hermetic Docker Container (Recommended)

```bash
# Clone the repository
git clone https://github.com/kamisaberi/sentinel-rt.git
cd sentinel-rt

# Build the hermetic fuzzing environment
docker build -t sentinel-rt:latest .

# Run the container with GPU access
docker run --gpus all -it --rm sentinel-rt:latest /bin/bash
```

### Option 2: Building Native C++ Harnesses from Source

```bash
# Create build directory
mkdir build && cd build

# Configure build with Clang & Sanitizers enabled
export CC=clang-18
export CXX=clang++-18

cmake .. -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DSENTINEL_ENABLE_ASAN=ON \
    -DSENTINEL_ENABLE_UBSAN=ON \
    -DSENTINEL_BUILD_HARNESSES=ON

# Compile core library and fuzzing harnesses
ninja
```

---

## 🚀 Usage Examples

### 1. Fuzzing GGUF Header Parsers with LibFuzzer & ASan

```bash
# Launch LibFuzzer harness with initial corpus
./bin/fuzz_gguf ../seeds/gguf/ \
    -max_len=1048576 \
    -workers=8 \
    -jobs=8 \
    -rss_limit_mb=4096
```

### 2. Launching Multi-Core AFL++ Fuzzing Campaign

```bash
# Run automated multi-core AFL++ fuzzing campaign
./scripts/run_afl.sh --target fuzz_safetensors --seeds ../seeds/safetensors --cores 16
```

### 3. Automated Crash Triaging & Deduplication

```bash
# Analyze crash dumps generated during fuzzing
python3 scripts/triage_crashes.py \
    --target ./bin/fuzz_gguf \
    --crashes ./out/crashes/ \
    --output ./reports/summary.json
```

---

## 📊 Directory Structure

```
sentinel-rt/
├── cmake/             # CMake modules for Sanitizers & CUDA configuration
├── include/sentinel/  # Public C++20 headers (fuzzer, parsers, sanitizers, triage)
├── src/               # Core C++ implementation files
├── harnesses/         # LibFuzzer & AFL++ entrypoint harnesses
├── mutators/          # Custom structure-aware AFL++ mutators (.so)
├── seeds/             # Seed corpus for GGUF, Safetensors, & ONNX formats
├── scripts/           # AFL++ campaign wrappers & crash triaging scripts
└── tests/             # Unit tests for core parsers and sanitizers
```

---

## 🛡️ Vulnerability Classification (CWE Coverage)

`sentinel-rt` is specifically configured to identify and report the following Common Weakness Enumerations:

- **CWE-119:** Improper Restriction of Operations within the Bounds of a Memory Buffer
- **CWE-122:** Heap-based Buffer Overflow
- **CWE-190:** Integer Overflow or Wraparound (Length/Dimension Calculations)
- **CWE-416:** Use After Free (UAF)
- **CWE-476:** NULL Pointer Dereference

---

## 📄 License

Distributed under the **Apache 2.0 License**. See [`LICENSE`](LICENSE) for more information.

---

## 👤 Author & Contact

**Kamran Saberifard**  
*Visionary AI Architect, High-Performance Systems & AI Security Engineer*  

- **ORCID:** [0009-0002-7822-6168](https://orcid.org/0009-0002-7822-6168)
- **GitHub:** [@kamisaberi](https://github.com/kamisaberi)
- **LinkedIn:** [kamisaberi](https://linkedin.com/in/kamisaberi)
- **Email:** [kamisaberi@gmail.com](mailto:kamisaberi@gmail.com)
```