# ============================================
# Multi-stage Dockerfile for Fuzzing Pipeline
# ============================================

# Stage 1: Build with sanitizers
FROM ubuntu:22.04 AS builder

RUN apt update && apt install -y \
    build-essential clang llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source files
COPY harness.cpp .
COPY hongg_harness.cpp .

# Compile with ASan + fuzzer
RUN clang++ -fsanitize=fuzzer,address \
    -g -O1 \
    -o fuzz_target harness.cpp

# Stage 2: Minimal runtime
FROM ubuntu:22.04

RUN apt update && apt install -y \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /fuzz

# Copy only binary and corpus
COPY --from=builder /build/fuzz_target .
COPY corpus/ ./corpus/

# Create crashes directory
RUN mkdir -p /crashes

# Default command: run fuzzer for 60 seconds
CMD ["./fuzz_target", "./corpus", "-artifact_prefix=/crashes/", "-max_total_time=60"]
