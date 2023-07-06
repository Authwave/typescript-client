import type { IncomingMessage, ServerResponse, RequestListener } from 'node:http';
import { Authenticator } from './authenticator.js';
import type { AuthenticatorOptions } from './authenticator.js';
import { RedirectSignal } from './redirect.js';
import { openSession } from './runtime.js';
import type { SessionOptions } from './runtime.js';
export { MemorySessionStore } from './runtime.js';
export type { SessionOptions, SessionStore } from './runtime.js';
export type RuntimeOptions = Omit<
	AuthenticatorOptions,
	'session' | 'currentUriPath' | 'redirectHandler'
> &
	SessionOptions;
export type NodeHandler = (
	auth: Authenticator,
	req: IncomingMessage,
) => string | Buffer | Promise<string | Buffer>;
/** Sends output only after session persistence. Handler must return its response body. */
export function createNodeHandler(options: RuntimeOptions, handler: NodeHandler): RequestListener {
	return async (req: IncomingMessage, res: ServerResponse) => {
		try {
			const context = await openSession(req.headers.cookie, options);
			let body: string | Buffer = '';
			let redirect: RedirectSignal | undefined;
			try {
				const auth = new Authenticator({
					...options,
					session: context.session,
					currentUriPath: req.url ?? '/',
				});
				body = await handler(auth, req);
			} catch (error) {
				if (error instanceof RedirectSignal) redirect = error;
				else throw error;
			} finally {
				await context.commit();
			}
			res.setHeader('Set-Cookie', context.setCookie);
			res.setHeader('Cache-Control', 'no-store');
			if (redirect) {
				res.writeHead(redirect.code, { Location: redirect.uri });
				res.end();
			} else {
				res.end(body);
			}
		} catch {
			if (!res.headersSent) res.writeHead(500);
			res.end('Internal Server Error');
		}
	};
}
