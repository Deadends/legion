FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin sidecar

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates openssl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/sidecar /usr/local/bin/
COPY sidecar/config.toml /etc/legion/config.toml
EXPOSE 8443 8080
CMD ["sidecar"]
