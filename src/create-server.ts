import { serve, type ServerType } from "@hono/node-server";
import { structuredLogger } from "@hono/structured-logger";
import { Hono, type Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { requestId } from "hono/request-id";
import type { CookieOptions } from "hono/utils/cookie";
import * as client from "openid-client";
import pino from "pino";
import * as setCookieParser from "set-cookie-parser";
import { z } from "zod";

import { SESSION_TTL, type SessionDatabase } from "./db.ts";
import { generateSessionToken } from "./util.ts";

type OIDCOptions = {
	config: client.Configuration;
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

const OAUTH_FLOW_TTL = Temporal.Duration.from({ minutes: 10 });

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
		? "__Host-Http-state"
		: "state";
	const PKCE_COOKIE_NAME = mergedCookieOptions.secure
		? "__Host-Http-pkce"
		: "pkce";
	const SESSION_COOKIE_NAME = mergedCookieOptions.secure
		? "__Host-Http-session"
		: "session";

	const redirectToAuth = async (c: Context, forwardedUrl: URL) => {
		const state = client.randomState();
		const codeVerifier = client.randomPKCECodeVerifier();
		const url = client.buildAuthorizationUrl(oidcOptions.config, {
			response_type: "code",
			redirect_uri: new URL(callbackPath, forwardedUrl.origin).toString(),
			scope: oidcOptions.scopes.join(" "),
			state,
			code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
			code_challenge_method: "S256",
		});

		setCookie(c, STATE_COOKIE_NAME, state, {
			...mergedCookieOptions,
			maxAge: OAUTH_FLOW_TTL.total("seconds"),
		});
		setCookie(c, PKCE_COOKIE_NAME, codeVerifier, {
			...mergedCookieOptions,
			maxAge: OAUTH_FLOW_TTL.total("seconds"),
		});

		return c.redirect(url.toString(), 302);
	};

	const handleCallback = async (c: Context, forwardedUrl: URL) => {
		const state = forwardedUrl.searchParams.get("state");

		const storedState = getCookie(c, STATE_COOKIE_NAME);
		const codeVerifier = getCookie(c, PKCE_COOKIE_NAME);
		deleteCookie(c, STATE_COOKIE_NAME, mergedCookieOptions);
		deleteCookie(c, PKCE_COOKIE_NAME, mergedCookieOptions);

		if (!storedState || !codeVerifier || state !== storedState) {
			return c.text("Invalid state or missing code. Please try again.", 400);
		}

		try {
			await client.authorizationCodeGrant(oidcOptions.config, forwardedUrl, {
				expectedState: storedState,
				pkceCodeVerifier: codeVerifier,
			});

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
				SESSION_TTL.total("seconds"),
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
			if (
				e instanceof client.ResponseBodyError ||
				e instanceof client.AuthorizationResponseError
			) {
				// Denied at the provider, or invalid code, PKCE verifier, credentials
				// or redirect URI
				return c.text(`Error: ${e.error}`, 401);
			}
			if (e instanceof TypeError && e.message === "fetch failed") {
				// Network-level failure calling the provider (DNS, connection, TLS).
				// Other TypeErrors are misuse/config errors and fall through to 500.
				const cause = e.cause;
				const detail =
					cause instanceof Error
						? cause.message ||
							// AggregateError with an empty message but a `code`
							("code" in cause && typeof cause.code === "string"
								? cause.code
								: "")
						: "";
				return c.text(`Error: ${detail || "Unknown"}`, 502);
			}
			if (e instanceof client.ClientError && e.code === "OAUTH_TIMEOUT") {
				return c.text("Error: identity provider timed out", 504);
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
			onRequest: (logger, c) => {
				logger.info(
					{ method: c.req.method, path: c.req.path },
					"request start",
				);
			},
			onResponse: (logger, c, elapsedMs) => {
				logger.info(
					{
						method: c.req.method,
						path: c.req.path,
						status: c.res.status,
						elapsedMs,
					},
					"request end",
				);
			},
			onError: (logger, err, c, elapsedMs) => {
				logger.error(
					{
						err,
						method: c.req.method,
						path: c.req.path,
						status: c.res.status,
						elapsedMs,
					},
					"request error",
				);
			},
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
