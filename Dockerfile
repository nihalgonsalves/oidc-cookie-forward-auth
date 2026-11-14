FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS builder

WORKDIR /app

COPY ./package.json /app/package.json
COPY ./pnpm-lock.yaml /app/pnpm-lock.yaml
COPY ./pnpm-workspace.yaml /app/pnpm-workspace.yaml

RUN npm install --global "$(node -p 'require("./package.json").packageManager.split("+")[0]')"

RUN pnpm install --prod --frozen-lockfile

FROM gcr.io/distroless/nodejs26-debian13:nonroot@sha256:1d736cf8b5716c07a245301f92717143215d248fd55771ee1936ef4b3302e531

WORKDIR /app

COPY --from=builder /app/node_modules /app/node_modules
COPY ./package.json /app/package.json
COPY ./tsconfig.json /app/tsconfig.json
COPY ./src /app/src

ENV NODE_ENV=production

USER nonroot
EXPOSE 3000/tcp
HEALTHCHECK --interval=5s --timeout=3s \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://localhost:3000/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

# - /app – application source (.ts, type-stripped at runtime) + node_modules
# - /var/lib/oidc/config – per-host config files imported dynamically by src/index.ts
# - net, naturally
# NOTE: SQLITE_PATH not implemented/checked by node:sqlite
ENTRYPOINT [ \
  "/nodejs/bin/node", \
  "--permission", \
  "--allow-fs-read=/app", \
  "--allow-fs-read=/var/lib/oidc/config", \
  "--allow-net", \
  "src/index.ts" \
]
