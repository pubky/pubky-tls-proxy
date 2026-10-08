# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/pubky-tls-proxy /usr/local/bin/pubky-tls-proxy
RUN mkdir -p /state/.pubky-tls-proxy

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /usr/local/bin/pubky-tls-proxy /usr/local/bin/pubky-tls-proxy
COPY --from=builder --chown=nonroot:nonroot /state/.pubky-tls-proxy /home/nonroot/.pubky-tls-proxy
VOLUME ["/home/nonroot/.pubky-tls-proxy"]
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/pubky-tls-proxy"]
