FROM ubuntu:22.04

RUN apt update && apt install -y \
    build-essential \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY harness.cpp .

RUN clang++ -fsanitize=fuzzer,address -g -O1 -o fuzz_target harness.cpp

RUN mkdir -p ./corpus ./crashes

RUN echo "test" > corpus/input1.txt && \
    echo "AAAA" > corpus/input2.txt && \
    echo "FUZZ" > corpus/input3.txt

ENV ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer

CMD ["./fuzz_target", "./corpus", "-artifact_prefix=./crashes/", "-max_total_time=60"]
