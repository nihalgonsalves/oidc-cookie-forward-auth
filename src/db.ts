import type { Database } from "bun:sqlite";
import { sha256 } from "@oslojs/crypto/sha2";
import { encodeHexLowerCase } from "@oslojs/encoding";

const CREATE_SESSION_TABLE_SQL = `
	CREATE TABLE IF NOT EXISTS session (
		id TEXT NOT NULL PRIMARY KEY,
		expires_at INTEGER NOT NULL,
		upstream_cookies TEXT NOT NULL
	);
`;

type Session = {
	id: string;
	expiresAt: Date;
	upstreamCookies: string;
};

export const encodeSessionToken = (token: string): string =>
	encodeHexLowerCase(sha256(new TextEncoder().encode(token)));

export class SessionDatabase {
	#db: Database;

	constructor(db: Database) {
		this.#db = db;
		this.#db.run(CREATE_SESSION_TABLE_SQL);
	}

	createSession = (token: string, upstreamCookies: string): Session => {
		const sessionId = encodeHexLowerCase(
			sha256(new TextEncoder().encode(token)),
		);

		const session: Session = {
			id: sessionId,
			expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
			upstreamCookies: upstreamCookies,
		};

		this.#db
			.query(
				"INSERT INTO session (id, expires_at, upstream_cookies) VALUES (?, ?, ?)",
			)
			.run(
				session.id,
				Math.floor(session.expiresAt.getTime() / 1000),
				upstreamCookies,
			);

		return session;
	};

	validateSessionToken = (token: string): Session | null => {
		const sessionId = encodeHexLowerCase(
			sha256(new TextEncoder().encode(token)),
		);

		const row = this.#db
			.query<
				{ id: string; expires_at: number; upstream_cookies: string },
				string
			>("SELECT id, expires_at, upstream_cookies FROM session WHERE id = ?")
			.get(sessionId);

		if (row == null) {
			return null;
		}

		const session: Session = {
			id: row.id,
			expiresAt: new Date(row.expires_at * 1000),
			upstreamCookies: row.upstream_cookies,
		};

		if (Date.now() >= session.expiresAt.getTime()) {
			this.#db
				.query("DELETE FROM session WHERE id = $id")
				.run({ id: session.id });
			return null;
		}

		if (Date.now() >= session.expiresAt.getTime() - 1000 * 60 * 60 * 24 * 15) {
			session.expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30);
			this.#db
				.query("UPDATE session SET expires_at = ? WHERE id = ?")
				.run(Math.floor(session.expiresAt.getTime() / 1000), session.id);
		}

		return session;
	};

	invalidateSession = (sessionId: string): void => {
		this.#db.query("DELETE FROM session WHERE id = ?").run(sessionId);
	};
}
