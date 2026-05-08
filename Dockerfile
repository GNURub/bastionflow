# syntax=docker/dockerfile:1

ARG BUN_VERSION=1

FROM oven/bun:${BUN_VERSION}-alpine AS base
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1 \
    BUN_INSTALL_CACHE_DIR=/tmp/bun-cache

FROM base AS deps
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

FROM base AS builder
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN bun --bun next build

FROM oven/bun:${BUN_VERSION}-alpine AS runner
WORKDIR /app

ARG VERSION=0.1.0
ARG REVISION=unknown
ARG SOURCE=https://github.com/GNURub/bastionflow
ARG CREATED=unknown

LABEL org.opencontainers.image.title="BastionFlow" \
      org.opencontainers.image.description="BastionFlow private CrowdSec operations dashboard with Traefik, Edge Gate, rate limits and optional notifications" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="MIT"

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN addgroup -S app \
  && adduser -S app -G app \
  && mkdir -p /data \
  && chown -R app:app /data /app

COPY --from=builder --chown=app:app /app/.next/standalone ./
COPY --from=builder --chown=app:app /app/.next/static ./.next/static
COPY --from=builder --chown=app:app /app/scripts ./scripts

USER app
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bun -e "const r = await fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/api/health'); process.exit(r.ok ? 0 : 1)"
CMD ["bun", "server.js"]
