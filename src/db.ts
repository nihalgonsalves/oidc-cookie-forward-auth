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

export const SESSION_TTL = Temporal.Duration.from({ hours: 24 * 30 });
const SESSION_RENEW_THRESHOLD = Temporal.Duration.from({ hours: 24 * 15 });

const toEpochSeconds = (instant: Temporal.Instant): number =>
	Math.floor(instant.epochMilliseconds / 1000);

type Session = {
	id: string;
	expiresAt: Temporal.Instant;
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
			expiresAt: Temporal.Now.instant().add(SESSION_TTL),
			upstreamCookies,
		};

		this.#db
			.prepare(
				"INSERT INTO session (id, expires_at, upstream_cookies) VALUES (?, ?, ?)",
			)
			.run(session.id, toEpochSeconds(session.expiresAt), upstreamCookies);

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
			expiresAt: Temporal.Instant.fromEpochMilliseconds(row.expires_at * 1000),
			upstreamCookies: row.upstream_cookies,
		};

		const now = Temporal.Now.instant();

		if (Temporal.Instant.compare(now, session.expiresAt) >= 0) {
			this.#db.prepare("DELETE FROM session WHERE id = ?").run(session.id);
			return null;
		}

		if (
			Temporal.Instant.compare(
				now,
				session.expiresAt.subtract(SESSION_RENEW_THRESHOLD),
			) >= 0
		) {
			session.expiresAt = now.add(SESSION_TTL);
			this.#db
				.prepare("UPDATE session SET expires_at = ? WHERE id = ?")
				.run(toEpochSeconds(session.expiresAt), session.id);
		}

		return session;
	};

	invalidateSession = (token: string): void => {
		this.#db
			.prepare("DELETE FROM session WHERE id = ?")
			.run(encodeSessionToken(token));
	};
}
