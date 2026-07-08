# Multi-Fuzzer Security Pipeline Dockerfile
FROM ubuntu:22.04 AS builder

RUN apt update && apt install -y \
    build-essential clang llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy harness
COPY harness.cpp .

# Build libFuzzer target
RUN clang++ -fsanitize=fuzzer,address \
    -g -O1 \
    -o fuzz_target harness.cpp

# Runtime stage
FROM ubuntu:22.04

RUN apt update && apt install -y \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /fuzz

# Copy binary
COPY --from=builder /build/fuzz_target .

# Create corpus directory if not exists
RUN mkdir -p ./corpus ./crashes

# Create default corpus files
RUN echo "test1" > corpus/input1.txt && \
    echo "AAAA" > corpus/input2.txt && \
    echo "FUZZ" > corpus/input3.txt

# Default command
CMD ["./fuzz_target", "./corpus", "-artifact_prefix=./crashes/", "-max_total_time=60"]
