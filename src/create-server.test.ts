import { DatabaseSync } from "node:sqlite";

import { serve, type ServerType } from "@hono/node-server";
import { serialize } from "cookie";
import { Hono } from "hono";
import * as setCookieParser from "set-cookie-parser";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createServer, type ServerOptions } from "./create-server.ts";
import { encodeSessionToken, SessionDatabase } from "./db.ts";

// oxlint-disable-next-line func-style
function expectToBeNotNullish<T>(
	value: T | undefined | null,
): asserts value is T {
	expect(value).not.toBeNull();
	expect(value).not.toBeUndefined();
}

const cleanups: (() => Promise<void>)[] = [];
afterAll(async () => {
	for (const stop of cleanups) {
		await stop();
	}
});

const startApp = async (app: Hono) => {
	let server: ServerType;
	const url = await new Promise<URL>((resolve) => {
		server = serve({ fetch: app.fetch, port: 0 }, (info) => {
			resolve(new URL(`http://localhost:${info.port}`));
		});
	});

	const stop = async (): Promise<void> => {
		if ("closeAllConnections" in server) {
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

const getRedirectLocation = (response: Response) => {
	expect(response.status).toBe(302);
	const locationHeader = response.headers.get("Location");
	expectToBeNotNullish(locationHeader);
	return new URL(locationHeader);
};

const createForwardAuthRequestHeaders = (url: URL) => ({
	"x-forwarded-proto": url.protocol.replace(":", ""),
	"x-forwarded-host": url.hostname,
	"x-forwarded-port": url.port,
	"x-forwarded-uri": `${url.pathname}${url.search}`,
});

const getCookiesFromResponse = (response: Response) =>
	setCookieParser.parseSetCookie(response.headers.getSetCookie());

const getClientCookieHeader = (cookies: setCookieParser.Cookie[]) =>
	cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");

type SimpleRequestInit = {
	headers?: Record<string, string>;
};

const createTestServers = async (serverOverrides: Partial<ServerOptions>) => {
	const db = new DatabaseSync(":memory:");

	const oauth2App = new Hono();
	oauth2App.get("/authorize", (c) => {
		const redirectUri = c.req.query("redirect_uri");
		const state = c.req.query("state");

		if (!redirectUri || !state) {
			return c.text("Missing redirect_uri or state", 400);
		}

		const redirect = new URL(redirectUri);
		redirect.searchParams.set("code", "test_code");
		redirect.searchParams.set("state", state);

		return c.redirect(redirect.toString(), 302);
	});
	oauth2App.all("/token", (c) =>
		c.json({
			access_token: "AAAA_ACCESS_TOKEN",
			token_type: "Bearer",
			expires_in: 3600,
			refresh_token: "aaaa_refresh_token",
			scope: "create",
		}),
	);
	const oauth2Server = await startApp(oauth2App);
	cleanups.push(oauth2Server.stop);

	const server = await createServer({
		serveOptions: { port: 0 },
		getHostConfig: async () => ({
			getUpstreamCookies: async () =>
				new Response("", {
					headers: {
						"Set-Cookie": serialize("test-cookie", "test-value", {
							expires: new Date(),
						}),
					},
				}),
			validateUpstreamSession: async () => true,
		}),
		oidcOptions: {
			clientId: "test-client-id",
			clientSecret: "test-client-secret",
			tokenEndpoint: new URL("/token", oauth2Server.url).toString(),
			authorizationEndpoint: new URL("/authorize", oauth2Server.url).toString(),
			scopes: ["openid", "email"],
		},
		db: new SessionDatabase(db),
		...serverOverrides,
	});
	cleanups.push(async () => {
		await server.stop(true);
	});

	const forwardAuthUrl = new URL("/oauth2/traefik", server.url);

	const fetchForwardAuth = async (url = server.url, init?: SimpleRequestInit) =>
		fetch(forwardAuthUrl, {
			...init,
			redirect: "manual",
			headers: {
				...createForwardAuthRequestHeaders(url),
				...init?.headers,
			},
		});

	return {
		server,
		oauth2Server,
		forwardAuthUrl,
		fetchForwardAuth,
		db,
	};
};

describe("createServer", () => {
	let testServers: Awaited<ReturnType<typeof createTestServers>>;

	beforeAll(async () => {
		testServers = await createTestServers({});
	});

	it("returns 200 on /healthz", async () => {
		const response = await fetch(new URL("/healthz", testServers.server.url));
		expect(response.status).toBe(200);
		expect(await response.text()).toBe("OK");
	});

	it("returns 400 unless x-forwarded headers are set", async () => {
		const response = await fetch(testServers.forwardAuthUrl);

		expect(response.status).toBe(400);
		expect(await response.text()).toBe("Invalid forward-auth request");
	});

	it("redirects to the authorization endpoint when not authenticated", async () => {
		const response = await testServers.fetchForwardAuth();

		expect(response.status).toBe(302);

		const locationHeader = response.headers.get("Location");
		expectToBeNotNullish(locationHeader);

		const location = new URL(locationHeader);

		expect(location.origin).toBe(testServers.oauth2Server.url.origin);
		expect(location.pathname).toBe("/authorize");

		expect(Object.fromEntries(location.searchParams)).toEqual({
			response_type: "code",
			client_id: "test-client-id",
			redirect_uri: new URL(
				"/oauth2/callback",
				testServers.server.url,
			).toString(),
			scope: "openid email",
			state: location.searchParams.get("state") ?? "",
		});
		expect(location.searchParams.get("state")).toBeDefined();
	});

	const completeOauth2Flow = async (
		testServerImpl: Awaited<ReturnType<typeof createTestServers>>,
		authorizeInit: SimpleRequestInit,
	) => {
		const initialResponse = await testServerImpl.fetchForwardAuth();
		const authResponse = await fetch(getRedirectLocation(initialResponse), {
			redirect: "manual",
		});
		return {
			initialResponse,
			authResponse,
			authorizeResponse: await testServerImpl.fetchForwardAuth(
				getRedirectLocation(authResponse),
				{
					...authorizeInit,
					headers: {
						cookie: getClientCookieHeader(
							getCookiesFromResponse(initialResponse),
						),
						...authorizeInit.headers,
					},
				},
			),
		};
	};

	it("returns an error if the state does not match", async () => {
		const { authorizeResponse } = await completeOauth2Flow(testServers, {
			headers: {
				cookie: "state=invalid_state;",
			},
		});
		expect(authorizeResponse.status).toBe(400);
		expect(await authorizeResponse.text()).toBe(
			"Invalid state or missing code. Please try again.",
		);
	});

	it("handles upstream request errors", async () => {
		const testServersWithUpstreamError = await createTestServers({
			getHostConfig: async () => ({
				getUpstreamCookies: async () => new Response("💥", { status: 502 }),
				validateUpstreamSession: async () => true,
			}),
		});

		const { authorizeResponse } = await completeOauth2Flow(
			testServersWithUpstreamError,
			{},
		);

		expect(authorizeResponse.status).toBe(502);
		expect(await authorizeResponse.text()).toBe(
			`Failed to authenticate with upstream service: 502`,
		);
	});

	it("handles upstream errors", async () => {
		const testServersWithUpstreamError = await createTestServers({
			getHostConfig: async (host) => {
				throw new Error(`${host} config not found`);
			},
		});

		const { authorizeResponse } = await completeOauth2Flow(
			testServersWithUpstreamError,
			{},
		);

		expect(authorizeResponse.status).toBe(502);
		expect(await authorizeResponse.text()).toMatch(/config not found/);
	});

	it("handles upstream revalidation", async () => {
		const testServersWithUpstreamError = await createTestServers({
			getHostConfig: async () => ({
				getUpstreamCookies: async () =>
					new Response("", {
						headers: {
							"Set-Cookie": serialize("test-cookie", "test-value", {
								expires: new Date(),
							}),
						},
					}),
				// Simulate an upstream session validation error
				validateUpstreamSession: async () => false,
			}),
		});

		// This passes because everything else is the same as the happy path
		const { authorizeResponse } = await completeOauth2Flow(
			testServersWithUpstreamError,
			{},
		);

		// But revalidating the session when making a normal forward-auth request fails
		const finalResponse = await testServersWithUpstreamError.fetchForwardAuth(
			undefined,
			{
				headers: {
					cookie: getClientCookieHeader(
						getCookiesFromResponse(authorizeResponse),
					),
				},
			},
		);
		expect(finalResponse.status).toBe(302);
	});

	it("handles invalid sessions", async () => {
		const { authorizeResponse } = await completeOauth2Flow(testServers, {});
		const cookies = getCookiesFromResponse(authorizeResponse);

		const sessionCookie = cookies.find((cookie) => cookie.name === "session");
		expectToBeNotNullish(sessionCookie);

		const okForwardAuthResponse = await testServers.fetchForwardAuth(
			new URL("/", testServers.server.url),
			{
				headers: {
					cookie: getClientCookieHeader(cookies),
				},
			},
		);
		expect(okForwardAuthResponse.status).toBe(200);

		testServers.db
			.prepare("DELETE FROM session WHERE id = ?")
			.run(encodeSessionToken(sessionCookie.value));

		const invalidSessionResponse = await testServers.fetchForwardAuth(
			new URL("/", testServers.server.url),
			{
				headers: {
					cookie: getClientCookieHeader(cookies),
				},
			},
		);
		expect(invalidSessionResponse.status).toBe(302);
	});

	it("successfully verifies an oauth2 token, authorizes a forward-auth response, and logs out", async () => {
		const { authorizeResponse } = await completeOauth2Flow(testServers, {});

		const finalResponse = await testServers.fetchForwardAuth(undefined, {
			headers: {
				cookie: getClientCookieHeader(
					getCookiesFromResponse(authorizeResponse),
				),
			},
		});
		expect(finalResponse.status).toBe(200);
		expect(await finalResponse.text()).toBe("OK");

		// We should also have any cookies from the mock `validateUpstreamSession`
		// response. These will be copied by Traefik to the actual origin request
		const upstreamCookies = finalResponse.headers.get("cookie");
		expect(upstreamCookies).toBe("test-cookie=test-value");

		// 5. Log out
		const logoutResponse = await testServers.fetchForwardAuth(
			new URL("/oauth2/logout", testServers.server.url),
			{
				headers: {
					cookie: getClientCookieHeader(
						getCookiesFromResponse(authorizeResponse),
					),
				},
			},
		);
		expect(logoutResponse.status).toBe(401);
		expect(await logoutResponse.text()).toBe(
			`Logged out successfully. Go to ${testServers.server.url.origin} to log in again.`,
		);
		expect(logoutResponse.headers.get("Clear-Site-Data")).toBe('"cookies"');
	});
});
