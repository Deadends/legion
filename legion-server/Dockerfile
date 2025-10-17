FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin legion-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/legion-server /usr/local/bin/
EXPOSE 3001
CMD ["legion-server"]
