import { serve, type ServerType } from "@hono/node-server";
import { structuredLogger } from "@hono/structured-logger";
import * as arctic from "arctic";
import { Hono, type Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { requestId } from "hono/request-id";
import type { CookieOptions } from "hono/utils/cookie";
import pino from "pino";
import * as setCookieParser from "set-cookie-parser";
import { z } from "zod";

import type { SessionDatabase } from "./db.ts";
import { generateSessionToken } from "./util.ts";

type OIDCOptions = {
	clientId: string;
	clientSecret: string;
	tokenEndpoint: string;
	authorizationEndpoint: string;
	scopes: string[];
};

export type HostConfig = {
	getUpstreamCookies: () => Promise<Response>;
	validateUpstreamSession: (headers: HeadersInit) => Promise<boolean>;
};

type ServeOptions = {
	port?: number;
	hostname?: string;
};

export type ServerOptions = {
	getHostConfig: (name: string) => Promise<HostConfig>;
	cookieOptions?: CookieOptions;
	oidcOptions: OIDCOptions;
	forwardAuthPath?: string;
	callbackPath?: string;
	logoutPath?: string;
	db: SessionDatabase;
	serveOptions?: ServeOptions;
};

export type Server = {
	url: URL;
	stop: (closeActiveConnections: boolean) => Promise<void>;
};

const defaultCookieOptions = {
	secure: process.env["NODE_ENV"] === "production",
	httpOnly: true,
	path: "/",
	sameSite: "Strict",
} satisfies CookieOptions;

const CookieInitSchema = z.object({
	name: z.string(),
	value: z.string(),
	domain: z.string().exactOptional(),
	path: z.string().exactOptional(),
	expires: z
		.union([z.date().transform((d) => d.toISOString()), z.number(), z.string()])
		.exactOptional(),
	secure: z.boolean().exactOptional(),
	sameSite: z
		.string()
		.transform((s) => s.toLowerCase())
		.pipe(z.enum(["strict", "lax", "none"]))
		.exactOptional(),
	httpOnly: z.boolean().exactOptional(),
	partitioned: z.boolean().exactOptional(),
	maxAge: z.number().exactOptional(),
});

const getCookieHeader = (cookies: { name: string; value: string }[]) =>
	cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");

export const createServer = async ({
	getHostConfig,
	cookieOptions,
	oidcOptions,
	forwardAuthPath = "/oauth2/traefik",
	callbackPath = "/oauth2/callback",
	logoutPath = "/oauth2/logout",
	db,
	serveOptions = {},
}: ServerOptions): Promise<Server> => {
	const mergedCookieOptions: CookieOptions = {
		...defaultCookieOptions,
		...cookieOptions,
	};

	const STATE_COOKIE_NAME = mergedCookieOptions.secure
		? "__Host-state"
		: "state";
	const SESSION_COOKIE_NAME = mergedCookieOptions.secure
		? "__Host-session"
		: "session";

	const getClient = (forwardedUrl: URL) =>
		new arctic.OAuth2Client(
			oidcOptions.clientId,
			oidcOptions.clientSecret,
			new URL(callbackPath, forwardedUrl.origin).toString(),
		);

	const redirectToAuth = (c: Context, forwardedUrl: URL) => {
		const state = arctic.generateState();
		const url = getClient(forwardedUrl).createAuthorizationURL(
			oidcOptions.authorizationEndpoint,
			state,
			oidcOptions.scopes,
		);

		setCookie(c, STATE_COOKIE_NAME, state, {
			...mergedCookieOptions,
			maxAge: 60 * 10, // 10 minutes
		});

		return c.redirect(url.toString(), 302);
	};

	const handleCallback = async (c: Context, forwardedUrl: URL) => {
		const { searchParams } = forwardedUrl;

		const code = searchParams.get("code");
		const state = searchParams.get("state");

		const storedState = getCookie(c, STATE_COOKIE_NAME);
		deleteCookie(c, STATE_COOKIE_NAME, mergedCookieOptions);

		if (!code || !storedState || state !== storedState) {
			return c.text("Invalid state or missing code. Please try again.", 400);
		}

		try {
			await getClient(forwardedUrl).validateAuthorizationCode(
				oidcOptions.tokenEndpoint,
				code,
				arctic.generateCodeVerifier(),
			);

			const token = generateSessionToken();

			let upstreamResponse: Response;
			try {
				const hostConfig = await getHostConfig(forwardedUrl.host);
				upstreamResponse = await hostConfig.getUpstreamCookies();
			} catch (error) {
				return c.text(
					`Failed to authenticate with upstream service: ${error instanceof Error ? error.message : "Unknown Error"}`,
					502,
				);
			}

			if (!upstreamResponse.ok) {
				return c.text(
					`Failed to authenticate with upstream service: ${upstreamResponse.status}`,
					502,
				);
			}

			const cookies = setCookieParser.parseSetCookie(
				upstreamResponse.headers.getSetCookie(),
			);

			const maxAge = Math.min(
				...cookies.map((cookie) => cookie.maxAge ?? Infinity),
				60 * 60 * 24 * 30, // 30 days
			);

			db.createSession(
				token,
				JSON.stringify(cookies.map((cookie) => CookieInitSchema.parse(cookie))),
			);

			setCookie(c, SESSION_COOKIE_NAME, token, {
				...mergedCookieOptions,
				maxAge,
			});

			return c.redirect(forwardedUrl.origin, 302);
		} catch (e) {
			if (e instanceof arctic.OAuth2RequestError) {
				// Invalid authorization code, credentials, or redirect URI
				return c.text(`Error: ${e.code}`, 401);
			}
			if (e instanceof arctic.ArcticFetchError) {
				// Failed to call `fetch()`
				const cause = e.cause;
				return c.text(
					`Error: ${cause instanceof Error ? cause.message : "Unknown"}`,
					502,
				);
			}
			// Parse error
			return c.text(
				`An unexpected error occurred: ${e instanceof Error ? e.message : "Unknown"}`,
				500,
			);
		}
	};

	const handleOtherRequests = async (c: Context, forwardedUrl: URL) => {
		const sessionToken = getCookie(c, SESSION_COOKIE_NAME);
		if (!sessionToken) {
			return redirectToAuth(c, forwardedUrl);
		}

		const session = db.validateSessionToken(sessionToken);
		if (session === null) {
			deleteCookie(c, SESSION_COOKIE_NAME, mergedCookieOptions);
			return redirectToAuth(c, forwardedUrl);
		}

		const cookies = z
			.array(CookieInitSchema)
			.parse(JSON.parse(session.upstreamCookies));

		const headers = {
			Cookie: getCookieHeader(cookies),
		};

		const hostConfig = await getHostConfig(forwardedUrl.host);
		if (!(await hostConfig.validateUpstreamSession(headers))) {
			deleteCookie(c, SESSION_COOKIE_NAME, mergedCookieOptions);
			db.invalidateSession(sessionToken);
			return redirectToAuth(c, forwardedUrl);
		}

		return c.body("OK", 200, headers);
	};

	const rootLogger = pino();

	const app = new Hono();

	app.use(requestId());
	app.use(
		structuredLogger({
			createLogger: (c) => rootLogger.child({ requestId: c.var.requestId }),
		}),
	);

	app.get("/healthz", (c) => c.text("OK", 200));

	app.all(forwardAuthPath, async (c) => {
		const proto = c.req.header("x-forwarded-proto");
		const host = c.req.header("x-forwarded-host");
		const port = c.req.header("x-forwarded-port");
		const path = c.req.header("x-forwarded-uri");

		if (!proto || !host || !port || !path) {
			return c.text("Invalid forward-auth request", 400);
		}

		const forwardedUrl = new URL(`${proto}://${host}:${port}${path}`);

		if (forwardedUrl.pathname === callbackPath) {
			return handleCallback(c, forwardedUrl);
		}

		if (forwardedUrl.pathname === logoutPath) {
			const sessionToken = getCookie(c, SESSION_COOKIE_NAME);
			if (sessionToken) {
				db.invalidateSession(sessionToken);
			}
			deleteCookie(c, SESSION_COOKIE_NAME, mergedCookieOptions);

			return c.body(
				`Logged out successfully. Go to ${forwardedUrl.origin} to log in again.`,
				// cannot return OK to forward-auth here, so use 401 even though it isn't appropriate
				401,
				{ "Clear-Site-Data": '"cookies"' },
			);
		}

		return handleOtherRequests(c, forwardedUrl);
	});

	let server: ServerType;
	const url = await new Promise<URL>((resolve) => {
		server = serve({ fetch: app.fetch, ...serveOptions }, (info) => {
			resolve(new URL(`http://localhost:${info.port}`));
		});
	});

	const stop = async (closeActiveConnections: boolean): Promise<void> => {
		if (closeActiveConnections && "closeAllConnections" in server) {
			server.closeAllConnections();
		}
		await new Promise<void>((resolve, reject) => {
			server.close((err) => {
				if (err) {
					reject(err);
				} else {
					resolve();
				}
			});
		});
	};

	return { url, stop };
};
