FROM rust:1-slim-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /src/target/release/pubky-tls-proxy /usr/local/bin/pubky-tls-proxy
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/pubky-tls-proxy"]
