import { Authenticator } from './authenticator.js';
import type { AuthenticatorOptions } from './authenticator.js';
import type { AuthUser } from './user.js';
import { GlobalSessionContainer, SessionData } from './session.js';
import { RedirectSignal } from './redirect.js';
import { SessionNotStartedException } from './errors.js';
export interface ExpressRequest {
	originalUrl: string;
	session?: object & {
		save(callback: (error?: unknown) => void): void;
		regenerate(callback: (error?: unknown) => void): void;
	};
}
export interface ExpressResponse {
	redirect(code: number, url: string): unknown;
	send(body: unknown): unknown;
	setHeader(name: string, value: string): unknown;
}
export type ExpressOptions = Omit<
	AuthenticatorOptions,
	'session' | 'currentUriPath' | 'redirectHandler'
>;
/** Mount after express-session. Save the result only after regenerating a newly authenticated session. */
export function createExpressHandler(
	options: ExpressOptions,
	handler: (auth: Authenticator, req: ExpressRequest) => unknown | Promise<unknown>,
) {
	return async (
		req: ExpressRequest,
		res: ExpressResponse,
		next: (error?: unknown) => void,
	): Promise<void> => {
		try {
			if (!req.session) throw new SessionNotStartedException('Mount express-session first');
			const staged: Record<string, unknown> = {};
			const original = req.session as Record<string, unknown>;
			if (Object.hasOwn(original, SessionData.STORE_KEY))
				staged[SessionData.STORE_KEY] = original[SessionData.STORE_KEY];
			let regenerate = false;
			let authenticated: AuthUser | undefined;
			let body: unknown;
			let failure: unknown;
			let failed = false;
			let redirect: RedirectSignal | undefined;
			try {
				const auth = new Authenticator({
					...options,
					currentUriPath: req.originalUrl,
					session: new GlobalSessionContainer(staged, () => {
						regenerate = true;
					}),
					onAuthenticated: options.onAuthenticated
						? (user) => {
								authenticated = user;
							}
						: undefined,
				});
				body = await handler(auth, req);
			} catch (error) {
				if (error instanceof RedirectSignal) redirect = error;
				else {
					failed = true;
					failure = error;
				}
			}
			try {
				if (regenerate) {
					const preserved = { ...req.session } as Record<string, unknown>;
					delete preserved[SessionData.STORE_KEY];
					await new Promise<void>((resolve, reject) =>
						req.session!.regenerate((error) => (error ? reject(error) : resolve())),
					);
					Object.assign(req.session!, preserved);
				}
				const target = req.session as Record<string, unknown>;
				if (Object.hasOwn(staged, SessionData.STORE_KEY))
					target[SessionData.STORE_KEY] = staged[SessionData.STORE_KEY];
				else delete target[SessionData.STORE_KEY];
				if (authenticated) options.onAuthenticated!(authenticated);
				if (failed) throw failure;
			} finally {
				if (req.session)
					await new Promise<void>((resolve, reject) =>
						req.session!.save((error) => (error ? reject(error) : resolve())),
					);
			}
			res.setHeader('Cache-Control', 'no-store');
			if (redirect) res.redirect(redirect.code, redirect.uri);
			else res.send(body);
		} catch (error) {
			next(error);
		}
	};
}
