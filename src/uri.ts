import { InsecureProtocolException } from './errors.js';
import type { Token } from './token.js';
export type UriLike = string | { toString(): string };
// Keep relative URIs and raw query strings: WHATWG URL alone normalizes both.
export class Uri {
	constructor(protected value: string = '') {}
	toString(): string {
		return this.value;
	}
	getQuery(): string {
		return this.value.split('#', 1)[0]!.split('?').slice(1).join('?');
	}
	getPath(): string {
		const s = this.value.split(/[?#]/, 1)[0]!;
		return /^[a-z][a-z\d+.-]*:\/\//i.test(s) ? new URL(s).pathname.replace(/^\/$/, '') || '' : s;
	}
	getScheme(): string {
		return /^([a-z][a-z\d+.-]*):/i.exec(this.value)?.[1] ?? '';
	}
	getHost(): string {
		try {
			return new URL(this.value).hostname;
		} catch {
			return '';
		}
	}
	getPort(): number | null {
		try {
			const p = new URL(this.value).port;
			return p ? Number(p) : null;
		} catch {
			return null;
		}
	}
	withQuery(query: string): Uri {
		const hash = this.value.indexOf('#');
		const fragment = hash < 0 ? '' : this.value.slice(hash);
		return new Uri(
			this.value.split(/[?#]/, 1)[0]! + (query ? `?${query.replace(/#/g, '%23')}` : '') + fragment,
		);
	}
	withoutQueryValue(key: string): Uri {
		const query = this.getQuery()
			.split('&')
			.filter((part) => decodeURIComponent(part.split('=', 1)[0]!) !== decodeURIComponent(key));
		return this.withQuery(query.join('&'));
	}
}
// PHP http_build_query uses RFC1738 (including escaping ! ' ( ) ~).
export function buildQuery(data: Record<string, string>): string {
	const encode = (s: string) =>
		encodeURIComponent(s)
			.replace(/[!'()~]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
			.replace(/%20/g, '+');
	return Object.entries(data)
		.map(([k, v]) => `${encode(k)}=${encode(v)}`)
		.join('&');
}
export abstract class BaseProviderUri extends Uri {
	static readonly DEFAULT_BASE_REMOTE_URI = 'login.authwave.com';
	static readonly QUERY_STRING_CIPHER = 'c';
	static readonly QUERY_STRING_INIT_VECTOR = 'i';
	static readonly QUERY_STRING_CURRENT_URI = 'u';
	static readonly QUERY_STRING_DEPLOYMENT_ID = 'd';
	constructor(baseUri: string) {
		const url = new URL(baseUri.includes('://') ? baseUri : `https://${baseUri}`);
		if (url.hostname !== 'localhost' && url.hostname !== '127.0.0.127' && url.protocol !== 'https:')
			throw new InsecureProtocolException(url.protocol.slice(0, -1));
		super(url.origin);
	}
	protected buildQuery(
		token: Token,
		deploymentId: string,
		currentPath: string,
		message = '',
	): string {
		return buildQuery({
			c: String(token.generateRequestCipher(message)),
			d: deploymentId,
			i: String(token.getIv()),
			u: Buffer.from(currentPath).toString('hex'),
		});
	}
}
export class LoginUri extends BaseProviderUri {
	constructor(
		token: Token,
		currentPath: string,
		deploymentId: string,
		baseRemoteUri = BaseProviderUri.DEFAULT_BASE_REMOTE_URI,
	) {
		super(baseRemoteUri);
		const message: Record<string, string> = { action: 'login' };
		const query = new Uri(currentPath).getQuery();
		if (query && query !== '0') message.returnQuery = query;
		this.value += `?${this.buildQuery(token, deploymentId, currentPath, buildQuery(message))}`;
	}
}
export class LogoutUri extends BaseProviderUri {
	constructor(
		token: Token,
		currentPath: string,
		deploymentId: string,
		baseRemoteUri = BaseProviderUri.DEFAULT_BASE_REMOTE_URI,
		redirectTo: UriLike | null = null,
	) {
		super(baseRemoteUri);
		const message: Record<string, string> = { action: 'logout' };
		if (redirectTo !== null) message.redirectTo = String(redirectTo);
		this.value += `?${this.buildQuery(token, deploymentId, currentPath, buildQuery(message))}`;
	}
}
export class AdminUri extends BaseProviderUri {
	constructor(baseRemoteUri: string) {
		super(baseRemoteUri);
		this.value += '/admin/';
	}
}
