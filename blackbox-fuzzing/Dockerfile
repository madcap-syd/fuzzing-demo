FROM ubuntu:22.04

RUN apt update && apt install -y gcc libc6-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /fuzz

COPY target.c .
RUN gcc -O2 -fno-stack-protector -z execstack -o target target.c

COPY fuzz.sh .
RUN chmod +x fuzz.sh

RUN mkdir -p corpus crashes

CMD ["./fuzz.sh"]
