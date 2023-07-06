import { randomBytes } from 'node:crypto';
import { GlobalSessionContainer } from './session.js';
export interface SessionStore {
	get(id: string): Promise<Record<string, unknown> | undefined>;
	set(id: string, data: Record<string, unknown>, expiresAt: number): Promise<void>;
}
/** Development only. Use a shared persistent store in production. */
export class MemorySessionStore implements SessionStore {
	private readonly sessions = new Map<
		string,
		{ data: Record<string, unknown>; expiresAt: number }
	>();
	async get(id: string): Promise<Record<string, unknown> | undefined> {
		const entry = this.sessions.get(id);
		if (!entry) return;
		if (entry.expiresAt <= Date.now()) {
			this.sessions.delete(id);
			return;
		}
		return JSON.parse(JSON.stringify(entry.data)) as Record<string, unknown>;
	}
	async set(id: string, data: Record<string, unknown>, expiresAt: number): Promise<void> {
		for (const [key, value] of this.sessions)
			if (value.expiresAt <= Date.now()) this.sessions.delete(key);
		this.sessions.set(id, {
			data: JSON.parse(JSON.stringify(data)) as Record<string, unknown>,
			expiresAt,
		});
	}
}
export interface SessionOptions {
	store: SessionStore;
	cookieName?: string;
	secureCookie?: boolean;
	ttlSeconds?: number;
}
export async function openSession(cookie: string | null | undefined, options: SessionOptions) {
	const name = options.cookieName ?? 'authwave.sid';
	if (!/^[\w.-]+$/.test(name)) throw new TypeError('Invalid cookie name');
	const ttl = options.ttlSeconds ?? 86400;
	if (!Number.isSafeInteger(ttl) || ttl <= 0)
		throw new RangeError('ttlSeconds must be a positive integer');
	const candidate = cookie
		?.split(';')
		.map((s) => s.trim())
		.find((s) => s.startsWith(`${name}=`))
		?.slice(name.length + 1);
	const stored =
		candidate && /^[a-f0-9]{64}$/.test(candidate) ? await options.store.get(candidate) : undefined;
	const id = stored ? candidate! : randomBytes(32).toString('hex');
	const data = stored ?? {};
	const setCookie = `${name}=${id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${ttl}${options.secureCookie === false ? '' : '; Secure'}`;
	return {
		session: new GlobalSessionContainer(data),
		setCookie,
		commit: () => options.store.set(id, data, Date.now() + ttl * 1000),
	};
}
