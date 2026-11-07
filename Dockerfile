# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags "-s -w -X github.com/pri-3x/txshield/internal/version.Version=${VERSION} -X github.com/pri-3x/txshield/internal/version.Commit=${COMMIT}" \
      -o /out/txshield ./cmd/txshield

# ---- anvil (fork simulation backend) ----
# Pinned Foundry release, verified against the SHA-256 published with it.
FROM debian:bookworm-slim AS foundry
ARG TARGETARCH
ARG FOUNDRY_VERSION=v1.8.5
ARG FOUNDRY_SHA256_AMD64=6c66ffcc55fa4249197721baa3098bc208014ea1d8aa04b2ed50ac6bccffb226
ARG FOUNDRY_SHA256_ARM64=5bdce3dade8b6f0a65d4fccf6908426aee4905a988b08dce79d0a72fe7498310
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) sha="${FOUNDRY_SHA256_AMD64}"; arch=amd64 ;; \
      arm64) sha="${FOUNDRY_SHA256_ARM64}"; arch=arm64 ;; \
      *) echo "unsupported architecture ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/foundry.tgz "https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_linux_${arch}.tar.gz"; \
    echo "${sha}  /tmp/foundry.tgz" | sha256sum -c -; \
    tar -xzf /tmp/foundry.tgz -C /usr/local/bin anvil; \
    /usr/local/bin/anvil --version

# ---- runtime ----
# anvil is dynamically linked against glibc (libc, libm, libgcc_s), so the
# runtime is distroless "cc" rather than "static".
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/txshield /usr/local/bin/txshield
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil
USER nonroot:nonroot
EXPOSE 8080
ENV TXSHIELD_HTTP_ADDR=:8080 \
    TXSHIELD_ANVIL_PATH=/usr/local/bin/anvil \
    HOME=/tmp
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/txshield", "healthcheck", "--url", "http://127.0.0.1:8080/health"]
ENTRYPOINT ["/usr/local/bin/txshield"]
CMD ["serve"]
