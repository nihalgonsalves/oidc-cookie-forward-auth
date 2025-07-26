import * as arctic from "arctic";
import type { CookieInit, HeadersInit } from "bun";
import type { SessionDatabase } from "./db";
import { generateSessionToken } from "./util";

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

export type ServerOptions = {
	getHostConfig: (name: string) => Promise<HostConfig>;
	cookieOptions?: CookieInit;
	oidcOptions: OIDCOptions;
	forwardAuthPath?: string;
	callbackPath?: string;
	logoutPath?: string;
	db: SessionDatabase;
	serveOptions?: Omit<Bun.ServeOptions, "fetch" | "routes">;
};

const defaultCookieOptions = {
	secure: process.env.NODE_ENV === "production",
	httpOnly: true,
	path: "/",
	sameSite: "strict",
} satisfies CookieInit;

export const createServer = ({
	getHostConfig,
	cookieOptions,
	oidcOptions,
	forwardAuthPath = "/oauth2/traefik",
	callbackPath = "/oauth2/callback",
	logoutPath = "/oauth2/logout",
	db,
	serveOptions = {},
}: ServerOptions) => {
	const mergedCookieOptions = {
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

	const redirectToAuth = (req: Bun.BunRequest, forwardedUrl: URL) => {
		const state = arctic.generateState();
		const url = getClient(forwardedUrl).createAuthorizationURL(
			oidcOptions.authorizationEndpoint,
			state,
			oidcOptions.scopes,
		);

		req.cookies.set(STATE_COOKIE_NAME, state, {
			...mergedCookieOptions,
			maxAge: 60 * 10, // 10 minutes
		});

		return Response.redirect(url.toString(), 302);
	};

	const getCookieHeader = (cookies: Bun.Cookie[]) =>
		cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");

	const handleCallback = async (req: Bun.BunRequest, forwardedUrl: URL) => {
		const { searchParams } = forwardedUrl;

		const code = searchParams.get("code");
		const state = searchParams.get("state");

		const storedState = req.cookies.get(STATE_COOKIE_NAME);
		req.cookies.delete(STATE_COOKIE_NAME, mergedCookieOptions);

		if (!code || !storedState || state !== storedState) {
			return new Response("Invalid state or missing code. Please try again.", {
				status: 400,
			});
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
				return new Response(
					`Failed to authenticate with upstream service: ${error instanceof Error ? error.message : "Unknown Error"}`,
					{ status: 502 },
				);
			}

			if (!upstreamResponse.ok) {
				return new Response(
					`Failed to authenticate with upstream service: ${upstreamResponse.status}`,
					{ status: 502 },
				);
			}

			const cookies = upstreamResponse.headers
				.getAll("set-cookie")
				.map((cookie) => new Bun.Cookie(cookie));

			const maxAge = Math.min(
				...cookies.map((cookie) => cookie.maxAge ?? Infinity),
				60 * 60 * 24 * 30, // 30 days
			);

			db.createSession(
				token,
				JSON.stringify(cookies.map((cookie) => cookie.toJSON())),
			);

			req.cookies.set(SESSION_COOKIE_NAME, token, {
				...mergedCookieOptions,
				maxAge,
			});

			return Response.redirect(forwardedUrl.origin, 302);
		} catch (e) {
			if (e instanceof arctic.OAuth2RequestError) {
				// Invalid authorization code, credentials, or redirect URI
				const code = e.code;
				return new Response(`Error: ${code}`, { status: 401 });
			}
			if (e instanceof arctic.ArcticFetchError) {
				// Failed to call `fetch()`
				const cause = e.cause;
				return new Response(
					`Error: ${cause instanceof Error ? cause.message : "Unknown"}`,
					{ status: 502 },
				);
			}
			// Parse error
			return new Response(
				`An unexpected error occurred: ${
					e instanceof Error ? e.message : "Unknown"
				}`,
				{ status: 500 },
			);
		}
	};

	const handleOtherRequests = async (
		req: Bun.BunRequest,
		forwardedUrl: URL,
	) => {
		const sessionToken = req.cookies.get(SESSION_COOKIE_NAME);
		if (!sessionToken) {
			return redirectToAuth(req, forwardedUrl);
		}

		const session = db.validateSessionToken(sessionToken);
		if (session === null) {
			req.cookies.delete(SESSION_COOKIE_NAME, mergedCookieOptions);
			return redirectToAuth(req, forwardedUrl);
		}

		const cookies = (JSON.parse(session.upstreamCookies) as string[]).map(
			(cookie) => new Bun.Cookie(cookie),
		);

		const headers = {
			Cookie: getCookieHeader(cookies),
		};

		const hostConfig = await getHostConfig(forwardedUrl.host);
		if (!(await hostConfig.validateUpstreamSession(headers))) {
			req.cookies.delete(SESSION_COOKIE_NAME, mergedCookieOptions);
			db.invalidateSession(sessionToken);
			return redirectToAuth(req, forwardedUrl);
		}

		return new Response("OK", {
			status: 200,
			headers,
		});
	};

	return Bun.serve({
		...serveOptions,
		routes: {
			"/healthz": () => new Response("OK", { status: 200 }),
			[forwardAuthPath]: async (req) => {
				const proto = req.headers.get("x-forwarded-proto");
				const host = req.headers.get("x-forwarded-host");
				const port = req.headers.get("x-forwarded-port");
				const path = req.headers.get("x-forwarded-uri");

				if (!proto || !host || !port || !path) {
					return new Response("Invalid forward-auth request", { status: 400 });
				}

				const forwardedUrl = new URL(`${proto}://${host}:${port}${path}`);

				if (forwardedUrl.pathname === callbackPath) {
					return handleCallback(req, forwardedUrl);
				}

				if (forwardedUrl.pathname === logoutPath) {
					req.cookies.delete(SESSION_COOKIE_NAME, mergedCookieOptions);

					return new Response(
						`Logged out successfully. Go to ${forwardedUrl.origin} to log in again.`,
						{
							// cannot return OK to forward-auth here, so use 401 even though it isn't appropriate
							status: 401,
							headers: { "Clear-Site-Data": '"cookies"' },
						},
					);
				}

				return handleOtherRequests(req, forwardedUrl);
			},
		},
	});
};
