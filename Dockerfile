# Hermetic Fuzzing Container for sentinel-rt
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install Clang 18, Build Tools, GDB, & AFL++
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang-18 \
    clang-tools-18 \
    llvm-18 \
    llvm-18-dev \
    lld-18 \
    cmake \
    ninja-build \
    git \
    python3 \
    python3-pip \
    gdb \
    lldb \
    libunwind-dev \
    aflplusplus \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set Clang 18 as default compilers
ENV CC=clang-18
ENV CXX=clang++-18

# Set up working directory
WORKDIR /workspace/sentinel-rt

# Copy source repository into container
COPY . .

# Build sentinel-rt with CMake & Ninja
RUN mkdir -p build && cd build && \
    cmake .. -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DSENTINEL_ENABLE_ASAN=ON \
        -DSENTINEL_ENABLE_UBSAN=ON \
        -DSENTINEL_BUILD_HARNESSES=ON && \
    ninja

CMD ["/bin/bash"]