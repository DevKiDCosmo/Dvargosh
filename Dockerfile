# ============================================================================
# Stage 1: Build & Verification Environment
# ============================================================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy source files
COPY CMakeLists.txt .
COPY include/ include/
COPY src/ src/
COPY modules/ modules/
COPY tests/ tests/

# Configure and build
RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release . && \
    cmake --build build --parallel

# Run verification tests inside builder stage
RUN ctest --test-dir build --output-on-failure --verbose

# ============================================================================
# Stage 2: Minimal Universal Runtime Container
# ============================================================================
FROM ubuntu:22.04 AS runner

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy artifacts from builder
COPY --from=builder /workspace/build/bin/dvargosh /app/bin/dvargosh
COPY --from=builder /workspace/build/bin/dvargosh_tests /app/bin/dvargosh_tests
COPY --from=builder /workspace/build/modules /app/modules

ENV PATH="/app/bin:${PATH}"
ENV LD_LIBRARY_PATH="/app/modules:${LD_LIBRARY_PATH}"

# Default command runs automated verification
CMD ["/app/bin/dvargosh", "--modules", "/app/modules"]
