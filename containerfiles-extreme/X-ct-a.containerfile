# SPDX-License-Identifier: MPL-2.0
# X-ct-a: eXtreme security attestation variant (Idris2 linear shadow + Ada/SPARK verification)

FROM ghcr.io/alire-project/alire:latest AS builder
WORKDIR /build

# Install crypto dependencies + Idris2
RUN apt-get update && apt-get install -y \
    gnat-13 \
    gprbuild \
    libcurl4-openssl-dev \
    libssl-dev \
    idris2 \
    && rm -rf /var/lib/apt/lists/*

COPY . /build

# Build with the Idris2 linear-type shadow model enabled
RUN alr build --release -- \
    -XCERRO_FEATURES=attestation \
    -XCERRO_BUILD_MODE=Release \
    -XCERRO_VERIFICATION=idris2-shadow

# Typecheck the Idris2 linear shadow model and build the ct-shadow checker
RUN cd verification/idris && idris2 --build cerro-torre.ipkg && \
    cd /build/tools/ct-shadow && idris2 --build ct-shadow.ipkg && \
    build/exec/ct-shadow --self-test

# Final image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates libcurl4 libssl3 curl chezscheme \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/bin/ct /usr/local/bin/
COPY --from=builder /build/tools/ct-shadow/build/exec/ /usr/local/lib/ct-shadow/
RUN ln -s /usr/local/lib/ct-shadow/ct-shadow /usr/local/bin/ct-shadow
RUN mkdir -p /etc/ct/keys /var/cache/ct

ENV CT_VARIANT=extreme-attestation
ENV CT_VERIFICATION=idris2-shadow+spark
ENV CT_SHADOW_VERIFIER=/usr/local/bin/ct-shadow
ENV CT_TRUST_STORE=/etc/ct/trust-store
ENV CT_KEY_DIR=/etc/ct/keys
LABEL org.opencontainers.image.description="Cerro Torre eXtreme Security Build (Idris2+SPARK) - Attestation variant"

ENTRYPOINT ["/usr/local/bin/ct"]
CMD ["--help"]
