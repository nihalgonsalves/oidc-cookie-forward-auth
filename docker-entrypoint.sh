#!/bin/sh
set -e

# - /app – application source (.ts, type-stripped at runtime) + node_modules
# - /var/lib/oidc/config – per-host config files imported dynamically by src/index.ts
set -- --permission \
	--allow-fs-read=/app \
	--allow-fs-read=/var/lib/oidc/config

# NOTE: not implemented/checked by node:sqlite
# if [ -n "$SQLITE_PATH" ]; then
# 	db_dir="$(dirname "$SQLITE_PATH")"
# 	set -- "$@" --allow-fs-read="$db_dir" --allow-fs-write="$db_dir"
# fi

# NOTE: for future Node 26 checks
# set -- "$@" --allow-net

exec node "$@" src/index.ts
