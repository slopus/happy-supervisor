# syntax=docker/dockerfile:1
# A release as Cloud Build builds it (deploy/cloudbuild.yaml), from the repository root as the
# context (filtered by Dockerfile.dockerignore): happy-supervisor for Linux on x86_64 and aarch64
# (musl, static, cross-built with cargo-zigbuild), SHA256SUMS over exactly those two, the
# installers and VERSION. It only builds; deploy/publish.sh signs and publishes. macOS and
# Windows are not built here: their SDKs cannot be fetched onto a Linux builder under their
# licences, so a release from here is partial. .github/workflows/release.yml builds all five.
#
#   DOCKER_BUILDKIT=1 docker build -f deploy/Dockerfile --build-arg VERSION=$(cat deploy/VERSION) \
#       --target release -o type=local,dest=<out> .
FROM rust:1.99-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS build
RUN set -eu; \
    [ "$(uname -m)" = x86_64 ] || { echo "the build runs on x86_64" >&2; exit 1; }; \
    curl -fsSL --proto "=https" --tlsv1.2 -o /tmp/zig.tar.xz \
        https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz; \
    echo "d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir /opt/zig; tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; rm /tmp/zig.tar.xz; \
    ln -s /opt/zig/zig /usr/local/bin/zig; \
    rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl; \
    cargo install --locked cargo-zigbuild@0.24.1
ARG VERSION
ENV CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0 \
    HAPPY_SUPERVISOR_VERSION=$VERSION
WORKDIR /src
COPY . .
RUN set -eu; \
    printf %s "$VERSION" | grep -Eq '^[0-9A-Za-z.+-]+$'; \
    [ "$VERSION" = "$(cat deploy/VERSION)" ] || { echo "VERSION is not deploy/VERSION" >&2; exit 1; }; \
    mkdir -p /out; \
    for t in x86_64:linux-x86_64 aarch64:linux-aarch64; do \
        target=${t%%:*}-unknown-linux-musl; \
        cargo zigbuild --locked --release --bin happy-supervisor --target "$target"; \
        cp "target/$target/release/happy-supervisor" "/out/happy-supervisor-${t##*:}"; \
    done; \
    for f in /out/happy-supervisor-*; do grep -aqF "$VERSION" "$f" || { echo "$f does not carry $VERSION" >&2; exit 1; }; done; \
    cd /out; sha256sum happy-supervisor-* > SHA256SUMS; cat SHA256SUMS; \
    cp /src/deploy/install.sh /src/deploy/install.ps1 /out/; printf "%s\n" "$VERSION" > /out/VERSION

FROM scratch AS release
COPY --from=build /out/ /happy-supervisor/
