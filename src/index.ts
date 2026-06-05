import { DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";

import {
	COOKIE_SECURE,
	DOMAIN_BASE,
	OIDC_OPTIONS,
	SQLITE_PATH,
} from "./config.ts";
import { createServer, type HostConfig } from "./create-server.ts";
import { SessionDatabase } from "./db.ts";

const hostCache = new Map<string, HostConfig>();

const server = await createServer({
	oidcOptions: OIDC_OPTIONS,
	cookieOptions: {
		secure: COOKIE_SECURE,
	},
	getHostConfig: async (name) => {
		const cachedValue = hostCache.get(name);
		if (cachedValue) {
			return cachedValue;
		}

		const filename = DOMAIN_BASE
			? name.replace(new RegExp(`${RegExp.escape(DOMAIN_BASE)}$`), "")
			: name;

		try {
			// oxlint-disable typescript/no-unsafe-assignment, typescript/no-unsafe-return, typescript/no-unsafe-argument
			const { config } = await import(
				pathToFileURL(`/var/lib/oidc/config/${filename}.ts`).href
			);

			hostCache.set(name, config);
			return config;
			// oxlint-enable typescript/no-unsafe-assignment, typescript/no-unsafe-return, typescript/no-unsafe-argument
		} catch (error) {
			throw new Error(
				`Could not load host config for ${name}: ${error instanceof Error ? error.message : "Unknown error"}. Make sure the file exists in /var/lib/oidc/config/${filename}.ts`,
				{ cause: error },
			);
		}
	},
	db: new SessionDatabase(new DatabaseSync(SQLITE_PATH ?? ":memory:")),
});

console.log(`Forward-auth server listening on ${server.url.toString()}`);

// oxlint-disable-next-line typescript/no-misused-promises
process.on("SIGTERM", async () => {
	await server.stop(false);
	process.exit();
});

// oxlint-disable-next-line typescript/no-misused-promises
process.on("SIGINT", async () => {
	await server.stop(true);
	process.exit();
});
