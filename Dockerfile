FROM oven/bun:1.2-alpine

WORKDIR /home/bun/app

COPY ./package.json /home/bun/app/package.json
COPY ./bun.lock /home/bun/app/bun.lock

RUN bun install --production --frozen-lockfile

COPY ./tsconfig.json /home/bun/app/tsconfig.json
COPY ./src /home/bun/app/src

ENV NODE_ENV=production

USER bun
EXPOSE 3000/tcp
HEALTHCHECK --interval=5s --timeout=3s \
  CMD wget -qO - http://localhost:3000/healthz || exit 1
ENTRYPOINT [ "bun", "run", "src/index.ts" ]
