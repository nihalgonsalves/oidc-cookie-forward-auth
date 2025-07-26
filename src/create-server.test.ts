import { Database } from "bun:sqlite";
import { describe, expect, it } from "bun:test";
import { createServer, type ServerOptions } from "./create-server";
import { encodeSessionToken, SessionDatabase } from "./db";

const randomInteger = (min: number, max: number) =>
	Math.floor(Math.random() * (max - min + 1)) + min;

function expectToBeNotNullish<T>(
	value: T | undefined | null,
): asserts value is T {
	expect(value).not.toBeNull();
	expect(value).not.toBeUndefined();
}

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
	response.headers
		.getAll("Set-Cookie")
		?.map((cookie) => Bun.Cookie.parse(cookie)) ?? [];

const getClientCookieHeader = (cookies: Bun.Cookie[]) =>
	cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");

const createTestServers = (serverOverrides: Partial<ServerOptions>) => {
	const db = new Database(":memory:", { strict: true });

	const oauth2Server = Bun.serve({
		port: randomInteger(4000, 10000),
		routes: {
			"/authorize": (req) => {
				const reqUrl = new URL(req.url);

				const redirectUri = reqUrl.searchParams.get("redirect_uri");
				const state = reqUrl.searchParams.get("state");

				if (!redirectUri || !state) {
					return new Response("Missing redirect_uri or state", { status: 400 });
				}

				const redirect = new URL(redirectUri);
				redirect.searchParams.set("code", "test_code");
				redirect.searchParams.set("state", state);

				return Response.redirect(redirect.toString(), 302);
			},
			"/token": () =>
				Response.json({
					access_token: "AAAA_ACCESS_TOKEN",
					token_type: "Bearer",
					expires_in: 3600,
					refresh_token: "aaaa_refresh_token",
					scope: "create",
				}),
		},
	});

	const server = createServer({
		serveOptions: { port: randomInteger(4000, 10000) },
		getHostConfig: async () => ({
			getUpstreamCookies: async () =>
				new Response("", {
					headers: {
						"Set-Cookie": new Bun.Cookie({
							name: "test-cookie",
							value: "test-value",
						}).serialize(),
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

	const forwardAuthUrl = new URL("/oauth2/traefik", server.url);

	const fetchForwardAuth = async (url = server.url, init?: RequestInit) =>
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

describe(createServer, async () => {
	const testServers = createTestServers({});

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

		expect(location.searchParams).toEqual(
			new URLSearchParams({
				response_type: "code",
				client_id: "test-client-id",
				redirect_uri: new URL(
					"/oauth2/callback",
					testServers.server.url,
				).toString(),
				scope: "openid email",
				state: location.searchParams.get("state") ?? "",
			}),
		);
		expect(location.searchParams.get("state")).toBeDefined();
	});

	const completeOauth2Flow = async (
		testServerImpl: ReturnType<typeof createTestServers>,
		authorizeInit: RequestInit,
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
		const testServersWithUpstreamError = createTestServers({
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
		const testServersWithUpstreamError = createTestServers({
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
		const testServersWithUpstreamError = createTestServers({
			getHostConfig: async () => ({
				getUpstreamCookies: async () =>
					new Response("", {
						headers: {
							"Set-Cookie": new Bun.Cookie({
								name: "test-cookie",
								value: "test-value",
							}).serialize(),
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

		testServers.db.exec("DELETE FROM session WHERE id = ?", [
			encodeSessionToken(sessionCookie.value),
		]);

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
