import * as client from "openid-client";
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

export const OIDC_OPTIONS = {
	config: await client.discovery(
		new URL(env.OIDC_ISSUER_CONFIG_URL),
		env.CLIENT_ID,
		// client_secret_post: avoids Basic-auth percent-encoding interop issues
		env.CLIENT_SECRET,
	),
	scopes: ["openid"],
};
