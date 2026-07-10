# UniSSH Server — multi-stage build → distroless, non-root (spec §14.1).
#
# IMPORTANT: the build context is the PARENT directory (which holds both `server/`
# and `rust-core/`), because the server dev-dependencies reference ../rust-core by
# path (byte-compat oracle). A release-binary build does NOT compile dev-deps, but
# cargo requires the paths to exist in order to parse the manifest.
#   docker build -f server/Dockerfile -t unissh-server ..
# (docker-compose is configured for this automatically.)

# Pin the builder to Debian 12 (bookworm, glibc 2.36) to MATCH the distroless
# cc-debian12 runtime below. Plain `rust:1.94-slim` tracks Debian 13 (glibc 2.38+),
# whose binaries fail on cc-debian12 with `GLIBC_2.38 not found`.
FROM rust:1.94-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev cmake clang && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# Cargo workspace root lives at the repo root (members = rust-core/crates/*, server);
# crates inherit [workspace.package] via `edition.workspace = true`, so the root
# Cargo.toml/Cargo.lock MUST be present or cargo fails with "workspace root not found".
COPY Cargo.toml Cargo.lock ./
COPY rust-core /build/rust-core
COPY server /build/server
RUN cargo build --release --bin unissh-server
RUN mkdir -p /out/data

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /build/target/release/unissh-server /usr/local/bin/unissh-server
COPY --from=builder /build/server/migrations /app/migrations
COPY --from=builder --chown=65532:65532 /out/data /app/data
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/unissh-server"]
CMD ["--config", "/app/config.toml"]
