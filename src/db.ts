import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

import { z } from "zod";

const SessionRowSchema = z.object({
	id: z.string(),
	expires_at: z.number(),
	upstream_cookies: z.string(),
});

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
	createHash("sha256").update(token).digest("hex");

export class SessionDatabase {
	#db: DatabaseSync;

	constructor(db: DatabaseSync) {
		this.#db = db;
		this.#db.exec(CREATE_SESSION_TABLE_SQL);
	}

	createSession = (token: string, upstreamCookies: string): Session => {
		const sessionId = encodeSessionToken(token);

		const session: Session = {
			id: sessionId,
			expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
			upstreamCookies,
		};

		this.#db
			.prepare(
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
		const sessionId = encodeSessionToken(token);

		const row = SessionRowSchema.nullable().parse(
			this.#db
				.prepare(
					"SELECT id, expires_at, upstream_cookies FROM session WHERE id = ?",
				)
				.get(sessionId) ?? null,
		);

		if (row == null) {
			return null;
		}

		const session: Session = {
			id: row.id,
			expiresAt: new Date(row.expires_at * 1000),
			upstreamCookies: row.upstream_cookies,
		};

		if (Date.now() >= session.expiresAt.getTime()) {
			this.#db.prepare("DELETE FROM session WHERE id = ?").run(session.id);
			return null;
		}

		if (Date.now() >= session.expiresAt.getTime() - 1000 * 60 * 60 * 24 * 15) {
			session.expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30);
			this.#db
				.prepare("UPDATE session SET expires_at = ? WHERE id = ?")
				.run(Math.floor(session.expiresAt.getTime() / 1000), session.id);
		}

		return session;
	};

	invalidateSession = (sessionId: string): void => {
		this.#db.prepare("DELETE FROM session WHERE id = ?").run(sessionId);
	};
}
