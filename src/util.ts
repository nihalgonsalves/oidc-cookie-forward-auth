import { randomBytes } from "node:crypto";

export const generateSessionToken = (): string =>
	randomBytes(20).toString("base64url");
