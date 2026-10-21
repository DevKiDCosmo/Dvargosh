# ============================================================================
# Stage 1: Build & Verification Environment
# ============================================================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    python3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy source repository components
COPY CMakeLists.txt .
COPY include/ include/
COPY src/ src/
COPY modules/ modules/
COPY development_modules/ development_modules/
COPY tests/ tests/
COPY pipeline_dvargosh/ pipeline_dvargosh/
COPY tools/ tools/
COPY docs/ docs/

# Run complete automated production pipeline & verification inside container
RUN chmod +x pipeline_dvargosh/build_production.sh && \
    ./pipeline_dvargosh/build_production.sh

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

# Copy production distribution from builder
COPY --from=builder /workspace/dist/ /app/

ENV PATH="/app/bin:${PATH}"
ENV LD_LIBRARY_PATH="/app/modules"

# Default command runs automated verification demonstration
CMD ["/app/bin/dvargosh", "--modules", "/app/modules"]
