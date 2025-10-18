# Multi-stage build for minimal production image
FROM rust:1.83-slim AS builder

WORKDIR /build

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY Cargo.toml Cargo.lock ./
COPY crypto_constants ./crypto_constants
COPY verifier ./verifier
COPY prover ./prover
COPY legion-server ./legion-server

# Build release binary
WORKDIR /build/legion-server
RUN cargo build --release --features redis

# Production image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 legion

# Copy binary
COPY --from=builder /build/legion-server/target/release/legion-server /usr/local/bin/

# Create data directory
RUN mkdir -p /data && chown legion:legion /data

USER legion
WORKDIR /data

EXPOSE 3001

CMD ["legion-server"]
