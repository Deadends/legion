# Multi-stage build for minimal production image
FROM rust:1.75-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY prover ./prover
COPY verifier ./verifier
COPY crypto_constants ./crypto_constants

# Build release binary
RUN cargo build --release --manifest-path prover/Cargo.toml

# Production stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /build/target/release/legion-prover /app/legion-prover

# Create data directory
RUN mkdir -p /app/legion_data

# Expose port
EXPOSE 3031

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3031/health || exit 1

# Run as non-root user
RUN useradd -m -u 1000 legion && chown -R legion:legion /app
USER legion

ENV RUST_LOG=info
ENV LEGION_DATA_PATH=/app/legion_data

CMD ["/app/legion-prover"]
