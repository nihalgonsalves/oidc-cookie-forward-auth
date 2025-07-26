import { z } from "zod";

export const zUrl = z.url({ protocol: /^https?$/ });

const ZEnvSchema = z.object({
	CLIENT_ID: z.string().min(1),
	CLIENT_SECRET: z.string().min(1),
	OIDC_ISSUER_CONFIG_URL: zUrl,
	SQLITE_PATH: z.string().min(1).optional(),
	DOMAIN_BASE: z.string().min(1).startsWith(".").optional(),
	UNSAFE_COOKIE_INSECURE: z
		.union([z.literal("true"), z.literal("1")])
		.optional(),
});

const env = ZEnvSchema.parse(process.env);
export const { SQLITE_PATH, DOMAIN_BASE } = env;

export const COOKIE_SECURE =
	env.UNSAFE_COOKIE_INSECURE !== "true" && env.UNSAFE_COOKIE_INSECURE !== "1";

const oidcConfigResponse = await fetch(env.OIDC_ISSUER_CONFIG_URL);
if (!oidcConfigResponse.ok) {
	throw new Error(
		`Failed to fetch OIDC configuration (${oidcConfigResponse.status})`,
	);
}

const ZOIDCDiscoverySchema = z.object({
	authorization_endpoint: zUrl,
	token_endpoint: zUrl,
	scopes_supported: z.array(z.string()),
});

export const oidcConfigJson = ZOIDCDiscoverySchema.parse(
	await oidcConfigResponse.json(),
);

export const OIDC_OPTIONS = {
	authorizationEndpoint: oidcConfigJson.authorization_endpoint,
	tokenEndpoint: oidcConfigJson.token_endpoint,
	scopes: ["openid"],
	clientId: env.CLIENT_ID,
	clientSecret: env.CLIENT_SECRET,
};
