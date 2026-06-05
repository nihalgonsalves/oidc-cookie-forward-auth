import { z } from "zod";

const zUrl = z.url({ protocol: /^https?$/ });

const ZEnvSchema = z.object({
	CLIENT_ID: z.string().min(1),
	CLIENT_SECRET: z.string().min(1),
	OIDC_ISSUER_CONFIG_URL: zUrl,
	SQLITE_PATH: z.string().min(1).optional(),
	DOMAIN_BASE: z.string().min(1).startsWith(".").optional(),
	UNSAFE_COOKIE_INSECURE: z.stringbool().optional().default(false),
});

const env = ZEnvSchema.parse(process.env);
export const { SQLITE_PATH, DOMAIN_BASE } = env;

export const COOKIE_SECURE = !env.UNSAFE_COOKIE_INSECURE;

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

const oidcConfigJson = ZOIDCDiscoverySchema.parse(
	await oidcConfigResponse.json(),
);

export const OIDC_OPTIONS = {
	authorizationEndpoint: oidcConfigJson.authorization_endpoint,
	tokenEndpoint: oidcConfigJson.token_endpoint,
	scopes: ["openid"],
	clientId: env.CLIENT_ID,
	clientSecret: env.CLIENT_SECRET,
};
