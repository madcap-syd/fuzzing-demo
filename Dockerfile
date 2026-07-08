# ============================================
# Multi-fuzzer Dockerfile
# libFuzzer (PR-Check) + HonggFuzz (Nightly)
# ============================================

# Stage 1: Build all fuzzers
FROM ubuntu:22.04 AS builder

RUN apt update && apt install -y \
    build-essential clang llvm \
    git make autoconf automake libtool \
    pkg-config libunwind-dev libblocksruntime-dev \
    binutils-dev libcapstone-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy harness files
COPY harness.cpp .
COPY hongg_harness.cpp .

# Build libFuzzer target
RUN clang++ -fsanitize=fuzzer,address \
    -g -O1 \
    -o fuzz_target_libfuzzer harness.cpp

# Build HonggFuzz target (without -fsanitize=fuzzer)
RUN clang++ -fsanitize=address \
    -g -O1 \
    -c hongg_harness.cpp -o hongg_harness.o

# Clone and build HonggFuzz
RUN git clone --depth 1 https://github.com/google/honggfuzz.git /honggfuzz-src \
    && cd /honggfuzz-src \
    && make -j$(nproc) \
    && cp honggfuzz /usr/local/bin/

# Stage 2: Runtime with both fuzzers
FROM ubuntu:22.04

RUN apt update && apt install -y \
    libstdc++6 libunwind8 libblocksruntime0 \
    libcapstone4 binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /fuzz

# Copy binaries
COPY --from=builder /build/fuzz_target_libfuzzer ./fuzz_target_libfuzzer
COPY --from=builder /usr/local/bin/honggfuzz /usr/local/bin/honggfuzz
COPY --from=builder /build/hongg_harness.o ./hongg_harness.o

# Link HonggFuzz target
RUN clang++ -fsanitize=address -o fuzz_target_honggfuzz hongg_harness.o 2>/dev/null || \
    cp fuzz_target_libfuzzer fuzz_target_honggfuzz

# Copy corpus
COPY corpus/ ./corpus/

# Create directories
RUN mkdir -p /crashes /corpus-merged

# Environment variables for fuzzer selection
ENV FUZZER=libfuzzer
ENV FUZZ_TIME=60

# Entrypoint script
RUN echo '#!/bin/bash\n\
if [ "$FUZZER" = "honggfuzz" ]; then\n\
    echo "[*] Running HonggFuzz (Nightly Deep Fuzzing)"\n\
    honggfuzz --input /corpus --output /crashes \n\
        --threads 2 --run_time ${FUZZ_TIME} \n\
        --rlimit_rss 1024 \n\
        --sanitizers coj \n\
        /fuzz/fuzz_target_honggfuzz\n\
else\n\
    echo "[*] Running libFuzzer (PR-Check)"\n\
    /fuzz/fuzz_target_libfuzzer /corpus \n\
        -artifact_prefix=/crashes/ \n\
        -max_total_time=${FUZZ_TIME} \n\
        -rss_limit_mb=1024\n\
fi' > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
