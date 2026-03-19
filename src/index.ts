import { Database } from "bun:sqlite";

import {
	COOKIE_SECURE,
	DOMAIN_BASE,
	OIDC_OPTIONS,
	SQLITE_PATH,
} from "./config";
import { createServer, type HostConfig } from "./create-server";
import { SessionDatabase } from "./db";

const hostCache = new Map<string, HostConfig>();

const server = createServer({
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
			const { config } = await import(`/var/lib/oidc/config/${filename}.ts`);

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
	db: new SessionDatabase(
		new Database(SQLITE_PATH ?? ":memory:", { strict: true }),
	),
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
