# syntax=docker/dockerfile:1
# Build context: repository root (needs sdk/typescript and frontend).
#   docker build -f frontend/Dockerfile .

FROM node:22-bookworm-slim AS build
ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /src

# SDK first: the dashboard installs it as a packed copy (install-links).
COPY sdk/typescript/package.json sdk/typescript/package-lock.json sdk/typescript/.npmrc sdk/typescript/
RUN cd sdk/typescript && npm ci --no-audit --no-fund
COPY sdk/typescript sdk/typescript
RUN cd sdk/typescript && npm run build

COPY frontend/package.json frontend/package-lock.json frontend/.npmrc frontend/
RUN cd frontend && npm ci --no-audit --no-fund
COPY frontend frontend
RUN cd frontend && npm run build

# Runtime: distroless Node, non-root, standalone output only.
FROM gcr.io/distroless/nodejs22-debian12:nonroot
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
WORKDIR /app
COPY --from=build /src/frontend/.next/standalone ./
USER nonroot:nonroot
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:3000/scan').then(r=>process.exit(r.status<500?0:1)).catch(()=>process.exit(1))"]
CMD ["server.js"]
