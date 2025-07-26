import { expect, it } from "bun:test";
import { generateSessionToken } from "./util";

it("generates a session token", () => {
	const token = generateSessionToken();

	expect(token.length).toBe(32);
});
