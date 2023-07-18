import { Authenticator } from './authenticator.js';
import { RedirectSignal } from './redirect.js';
import { openSession } from './runtime.js';
import type { RuntimeOptions } from './node.js';
export { MemorySessionStore } from './runtime.js';
export type { SessionOptions, SessionStore } from './runtime.js';
export type { RuntimeOptions } from './node.js';
/** App Router Route Handler, Node.js runtime. Uses Next.js's native Request/Response contract. */
export function createNextHandler(
	options: RuntimeOptions,
	handler: (auth: Authenticator, request: Request) => Response | Promise<Response>,
) {
	return async (request: Request): Promise<Response> => {
		const context = await openSession(request.headers.get('cookie'), options);
		let response: Response;
		try {
			const url = new URL(request.url);
			const auth = new Authenticator({
				...options,
				session: context.session,
				currentUriPath: url.pathname + url.search,
			});
			response = await handler(auth, request);
		} catch (error) {
			if (!(error instanceof RedirectSignal)) throw error;
			response = new Response(null, {
				status: error.code,
				headers: { Location: new URL(error.uri, request.url).href },
			});
		} finally {
			await context.commit();
		}
		// Copy because fetch() and Response.redirect() may return immutable headers.
		const result = new Response(response.body, response);
		result.headers.append('Set-Cookie', context.setCookie);
		result.headers.set('Cache-Control', 'no-store');
		return result;
	};
}
