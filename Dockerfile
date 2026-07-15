FROM ubuntu:24.04@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9 AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake \
        g++ \
        git \
        make \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cmake -S . -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DORCHARDSEAL_BUILD_TESTS=ON \
        -DORCHARDSEAL_WARNINGS_AS_ERRORS=ON \
    && cmake --build build --parallel \
    && ctest --test-dir build --output-on-failure

FROM ubuntu:24.04@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9 AS runtime
RUN apt-get update \
    && if apt-cache show libssl3t64 >/dev/null 2>&1; then \
        apt-get install -y --no-install-recommends libssl3t64 ca-certificates; \
    else \
        apt-get install -y --no-install-recommends libssl3 ca-certificates; \
    fi \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/orchardseal /usr/local/bin/orchardseal
ENTRYPOINT ["orchardseal"]
