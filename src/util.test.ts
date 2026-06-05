import { expect, it } from "vitest";

import { generateSessionToken } from "./util.ts";

it("generates a session token", () => {
	const token = generateSessionToken();

	// 20 random bytes encoded as base64url (no padding)
	expect(token.length).toBe(27);
});
