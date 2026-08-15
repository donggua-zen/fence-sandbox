FROM debian:bookworm

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
