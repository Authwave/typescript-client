import { NotLoggedInException, SessionNotStartedException } from './errors.js';
import { Token } from './token.js';
import { BaseResponseData, UserResponseData } from './user.js';
export class SessionData {
	static readonly STORE_KEY = 'Authwave\\SessionData';
	private callbackInvoked = false;
	constructor(
		private readonly token: Token | null = null,
		private readonly data: BaseResponseData | null = null,
		private readonly returnQuery: string | null = null,
	) {}
	getToken(): Token {
		if (!this.token) throw new NotLoggedInException();
		return this.token;
	}
	getData(): BaseResponseData {
		if (!this.data) throw new NotLoggedInException();
		return this.data;
	}
	getReturnQuery(): string | null {
		return this.returnQuery;
	}
	hasInvokedAuthenticationCallback(): boolean {
		return this.callbackInvoked;
	}
	markAuthenticationCallbackInvoked(): void {
		this.callbackInvoked = true;
	}
	toJSON() {
		return {
			token: this.token?.toJSON() ?? null,
			data:
				this.data instanceof UserResponseData
					? {
							id: this.data.getId(),
							email: this.data.getEmail(),
							kvp: this.data.getAllFields(),
							message: this.data.getMessage(),
						}
					: null,
			returnQuery: this.returnQuery,
			callbackInvoked: this.callbackInvoked,
		};
	}
	static fromJSON(value: ReturnType<SessionData['toJSON']>): SessionData {
		const data = new SessionData(
			value.token ? Token.fromJSON(value.token) : null,
			value.data
				? new UserResponseData(value.data.id, value.data.email, value.data.kvp, value.data.message)
				: null,
			value.returnQuery,
		);
		if (value.callbackInvoked) data.markAuthenticationCallbackInvoked();
		return data;
	}
}
export interface SessionContainer {
	get(key: string): unknown;
	set(key: string, value: unknown): void;
	contains(key: string): boolean;
	remove(key: string): void;
}
/** Wrap an existing request-scoped session; never a process-global session. */
export class GlobalSessionContainer implements SessionContainer {
	constructor(private readonly data?: Record<string, unknown>) {
		if (!data) throw new SessionNotStartedException();
	}
	get(key: string): unknown {
		const value = this.data![key];
		return key === SessionData.STORE_KEY && value && !(value instanceof SessionData)
			? SessionData.fromJSON(value as ReturnType<SessionData['toJSON']>)
			: value;
	}
	set(key: string, value: unknown): void {
		this.data![key] = value;
	}
	contains(key: string): boolean {
		return Object.hasOwn(this.data!, key);
	}
	remove(key: string): void {
		delete this.data![key];
	}
}
export { GlobalSessionContainer as SessionArrayWrapper };
