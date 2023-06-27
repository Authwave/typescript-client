import type { UriLike } from './uri.js';
/** Control-flow signal caught by runtime adapters; prevents execution after redirects. */
export class RedirectSignal extends Error {
	constructor(
		public readonly uri: string,
		public readonly code = 303,
	) {
		super(`Redirect to ${uri}`);
		this.name = 'RedirectSignal';
	}
}
export class RedirectHandler {
	redirect(uri: UriLike, code = 303): void {
		throw new RedirectSignal(String(uri), code);
	}
}
