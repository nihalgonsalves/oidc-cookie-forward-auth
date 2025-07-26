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
			? name.replace(
					// @ts-expect-error ts types for a new method
					new RegExp(`${RegExp.escape(DOMAIN_BASE)}$`),
					"",
				)
			: name;

		try {
			const { config } = await import(`/var/lib/oidc/config/${filename}.ts`);

			hostCache.set(name, config);
			return config;
		} catch (error) {
			throw new Error(
				`Could not load host config for ${name}: ${error instanceof Error ? error.message : "Unknown error"}. Make sure the file exists in /var/lib/oidc/config/${filename}.ts`,
			);
		}
	},
	db: new SessionDatabase(
		new Database(SQLITE_PATH ?? ":memory:", { strict: true }),
	),
});

console.log(`Forward-auth server listening on ${server.url}`);

process.on("SIGTERM", async () => {
	await server.stop(false);
	process.exit();
});

process.on("SIGINT", async () => {
	await server.stop(true);
	process.exit();
});
