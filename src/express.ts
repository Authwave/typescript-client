import { Authenticator } from './authenticator.js';
import type { AuthenticatorOptions } from './authenticator.js';
import { GlobalSessionContainer } from './session.js';
import { RedirectSignal } from './redirect.js';
import { SessionNotStartedException } from './errors.js';
export interface ExpressRequest {
	originalUrl: string;
	session?: object & { save(callback: (error?: unknown) => void): void };
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
/** Mount after express-session. Return a body; this adapter saves before sending it. */
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
			let body: unknown;
			let redirect: RedirectSignal | undefined;
			try {
				const auth = new Authenticator({
					...options,
					currentUriPath: req.originalUrl,
					session: new GlobalSessionContainer(req.session as Record<string, unknown>),
				});
				body = await handler(auth, req);
			} catch (error) {
				if (error instanceof RedirectSignal) redirect = error;
				else throw error;
			} finally {
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
