FROM node:26-alpine

RUN corepack enable

WORKDIR /app

COPY ./package.json /app/package.json
COPY ./pnpm-lock.yaml /app/pnpm-lock.yaml

RUN pnpm install --prod --frozen-lockfile

COPY ./tsconfig.json /app/tsconfig.json
COPY ./src /app/src
COPY --chmod=0755 ./docker-entrypoint.sh /app/docker-entrypoint.sh

ENV NODE_ENV=production

USER node
EXPOSE 3000/tcp
HEALTHCHECK --interval=5s --timeout=3s \
  CMD wget -qO - http://localhost:3000/healthz || exit 1
ENTRYPOINT [ "/app/docker-entrypoint.sh" ]
