import { expect, it } from "vitest";

import { generateSessionToken } from "./util.ts";

it("generates a session token", () => {
	const token = generateSessionToken();

	expect(token.length).toBe(32);
});
