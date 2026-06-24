# syntax=docker/dockerfile:1.7
#
# noir/bb DCAP prove server image (the single prover; replaces the gnark
# prove-server image). Bundles the Rust prove service + the Go witness
# generator (genprover) + the nargo/bb toolchain + the compiled dcap-noir
# circuit, and serves /prove over a unix socket.
#
# Build context: the zkdcap repo root.
#   cd /Users/mvid/Development/reliq/zkdcap
#   docker build --platform linux/amd64 -f noir-prove-server/Dockerfile \
#     -t ghcr.io/burnt-labs/dossier-noir-prove-server:dcap-ultrahonk-v1 .
#
# The vk is already on-chain (xiond tx zk add-vkey dcap-ultrahonk-v1, id 15);
# the image bakes the compiled circuit so the prover starts without recompiling.
#
# NOTE (validate on first real build): the nargo/bb versions MUST match Xion's
# live verifier (barretenberg-go v0.4.0 == nargo 1.0.0-beta.19 + bb 4.0.4). The
# installer version strings below are pinned to that pairing; confirm them
# against a real build (the bbup<->bb version mapping in particular).

ARG NARGO_VERSION=1.0.0-beta.19
ARG BB_VERSION=0.84.0   # bbup tag that ships the bb 4.0.4 ACIR/proof format

# ---------------------------------------------------------------------------
# Rust builder: the prove service
# ---------------------------------------------------------------------------
FROM rust:1.94.1-slim-bookworm AS rust-builder
WORKDIR /build
COPY noir-prove-server/ ./noir-prove-server/
RUN cd noir-prove-server && cargo build --release && \
    cp target/release/noir-prove-server /out-noir-prove-server

# ---------------------------------------------------------------------------
# Go builder: the witness generator (genprover)
# ---------------------------------------------------------------------------
FROM golang:1.24-bookworm AS go-builder
WORKDIR /build
COPY circuits/dcap-noir/tools/ ./tools/
RUN cd tools && CGO_ENABLED=0 go build -trimpath -o /out-genprover genprover.go toml.go

# ---------------------------------------------------------------------------
# Toolchain + circuit: install nargo + bb, compile the circuit
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS circuit
ARG NARGO_VERSION
ARG BB_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git bash libstdc++6 && \
    rm -rf /var/lib/apt/lists/*
ENV PATH=/root/.nargo/bin:/root/.bb:$PATH
# noir (nargo) + barretenberg (bb), pinned to Xion's live verifier pairing.
RUN curl -fsSL https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && \
    /root/.nargo/bin/noirup -v ${NARGO_VERSION}
RUN curl -fsSL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash && \
    /root/.bb/bbup -v ${BB_VERSION}
# Compile the circuit + write the vk so the server starts without recompiling.
COPY circuits/dcap-noir/ /circuit/
RUN cd /circuit && nargo compile --package dcap_full && \
    bb write_vk -s ultra_honk -b target/dcap_full.json -o target && \
    mv target/vk target/dcap_full.vk

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libstdc++6 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10003 prover && \
    useradd -u 10003 -g prover -s /sbin/nologin -m -d /home/prover prover

# nargo + bb toolchain, the compiled circuit, and the two binaries.
COPY --from=circuit /root/.nargo/bin/nargo /usr/local/bin/nargo
COPY --from=circuit /root/.bb/bb           /usr/local/bin/bb
COPY --from=circuit /circuit               /opt/dcap-noir
COPY --from=rust-builder /out-noir-prove-server /usr/local/bin/noir-prove-server
COPY --from=go-builder   /out-genprover         /usr/local/bin/genprover

RUN mkdir -p /run/noir && chown -R prover:prover /run/noir /opt/dcap-noir
USER prover:prover
ENV ZKDCAP_PROVER_SOCKET=/run/noir/prove.sock \
    NOIR_WORKSPACE=/opt/dcap-noir \
    GENPROVER_BIN=/usr/local/bin/genprover \
    NARGO_BIN=/usr/local/bin/nargo \
    BB_BIN=/usr/local/bin/bb
ENTRYPOINT ["/usr/local/bin/noir-prove-server"]
