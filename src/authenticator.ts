import { CipherText, decrypt, InitVector } from './cipher.js';
import { NotLoggedInException } from './errors.js';
import { RedirectHandler } from './redirect.js';
import { GlobalSessionContainer, SessionData } from './session.js';
import type { SessionContainer } from './session.js';
import { Token } from './token.js';
import { AuthUser, User, UserResponseData } from './user.js';
import { AdminUri, BaseProviderUri, buildQuery, LoginUri, LogoutUri, Uri } from './uri.js';
import type { UriLike } from './uri.js';
export interface AuthenticatorOptions {
	clientKey: string;
	currentUriPath: UriLike;
	authwaveHost?: string;
	session?: SessionContainer;
	redirectHandler?: RedirectHandler;
	onAuthenticated?: (user: AuthUser) => void;
}
export class Authenticator {
	static readonly SESSION_STORE_KEY = 'AUTHWAVE_CONSUMER_SESSION';
	static readonly RESPONSE_QUERY_PARAMETER = 'AUTHWAVE_RESPONSE_DATA';
	static readonly FAKE_EMAIL = 'fakelogin@authwave.com';
	private sessionData?: SessionData;
	private user?: User;
	private readonly currentUriPath: Uri;
	private returnUri: Uri | null = null;
	private readonly session: SessionContainer;
	private readonly redirectHandler: RedirectHandler;
	private readonly deploymentId: string;
	private readonly secret: string;
	private readonly host: string;
	constructor(private readonly options: AuthenticatorOptions) {
		const split = options.clientKey.lastIndexOf('_');
		this.deploymentId = split < 0 ? '' : options.clientKey.slice(0, split);
		this.secret = split < 0 ? '' : options.clientKey.slice(split + 1);
		this.host = options.authwaveHost ?? BaseProviderUri.DEFAULT_BASE_REMOTE_URI;
		this.session = options.session ?? new GlobalSessionContainer();
		this.redirectHandler = options.redirectHandler ?? new RedirectHandler();
		this.sessionData = this.session.get(SessionData.STORE_KEY) as SessionData | undefined;
		if (this.sessionData) {
			try {
				const data = this.sessionData.getData();
				if (data instanceof UserResponseData) this.user = new User(data.getId(), data.getEmail());
			} catch (error) {
				if (!(error instanceof NotLoggedInException)) throw error;
			}
		}
		this.currentUriPath = new Uri(String(options.currentUriPath));
		this.completeAuth();
	}
	setReturnUri(uri: string): void {
		this.returnUri = new Uri(uri);
	}
	isLoggedIn(): boolean {
		return this.user !== undefined;
	}
	login(token: Token | null = null): void {
		if (this.isLoggedIn()) return;
		token ??= new Token(this.secret);
		const loginUri = this.getLoginUri(token);
		this.sessionData = new SessionData(
			token,
			null,
			(this.returnUri ?? this.currentUriPath).getQuery(),
		);
		this.session.set(SessionData.STORE_KEY, this.sessionData);
		this.redirectHandler.redirect(loginUri);
	}
	logout(redirectTo: UriLike | null = null, token: Token | null = null): void {
		const isFake = this.user?.email === Authenticator.FAKE_EMAIL;
		this.session.remove(SessionData.STORE_KEY);
		delete this.user;
		delete this.sessionData;
		if (isFake) return;
		token ??= new Token(this.secret);
		redirectTo ??= this.returnUri;
		if (typeof redirectTo === 'string' && redirectTo.startsWith('?'))
			redirectTo = this.currentUriPath.withQuery(redirectTo.slice(1));
		this.redirectHandler.redirect(
			new LogoutUri(
				token,
				String(this.returnUri ?? this.currentUriPath),
				this.deploymentId,
				this.host,
				redirectTo,
			),
		);
	}
	fakeLogin(userId: string, email: string | null = null, redirectTo = '/'): void {
		const iv = new InitVector();
		const token = new Token(this.secret, iv);
		this.session.set(SessionData.STORE_KEY, new SessionData(token));
		const data = new UserResponseData(userId, email ?? Authenticator.FAKE_EMAIL);
		this.session.set(SessionData.STORE_KEY, new SessionData(token, data));
		const cipher = new CipherText(
			JSON.stringify({ id: data.getId(), email: data.getEmail() }),
			iv,
			this.secret,
		);
		this.redirectHandler.redirect(
			new Uri(`${redirectTo}?${buildQuery({ AUTHWAVE_RESPONSE_DATA: String(cipher) })}`),
		);
	}
	getAuthUser(): AuthUser {
		if (!this.user) throw new NotLoggedInException();
		return this.user;
	}
	/** @deprecated Use getAuthUser(). */
	getUser(): User {
		process.emitWarning(
			'Authenticator::getUser() is deprecated; use getAuthUser() instead.',
			'DeprecationWarning',
		);
		if (!this.user) throw new NotLoggedInException();
		return this.user;
	}
	getLoginUri(token: Token): BaseProviderUri {
		return new LoginUri(
			token,
			String(this.returnUri ?? this.currentUriPath),
			this.deploymentId,
			this.host,
		);
	}
	getAdminUri(): Uri {
		return new AdminUri(this.host);
	}
	private completeAuth(): void {
		const query = new URLSearchParams(this.currentUriPath.getQuery());
		const values = query.getAll(Authenticator.RESPONSE_QUERY_PARAMETER);
		const queryData = values.at(-1)?.replace(/ /g, '+');
		if (!queryData || queryData === '0') return;
		if (!this.sessionData) {
			this.tidyResponseData();
			return;
		}
		const token = this.sessionData.getToken();
		const returnQuery = this.sessionData.getReturnQuery();
		const plain = decrypt(queryData, token.getSecretIv(), this.secret);
		let data: { id?: unknown; email?: unknown };
		try {
			data = JSON.parse(plain);
		} catch {
			throw new TypeError('Invalid authentication response');
		}
		// Match the reference's non-strict scalar coercion.
		const scalar = (value: unknown): string => {
			if (typeof value === 'string' || typeof value === 'number') return String(value);
			if (typeof value === 'boolean') return value ? '1' : '';
			throw new TypeError('Expected user id/email scalar');
		};
		const userData = new UserResponseData(scalar(data?.id), scalar(data?.email));
		this.user = new User(userData.getId(), userData.getEmail());
		const wasInvoked = this.sessionData.hasInvokedAuthenticationCallback();
		const next = new SessionData(token, userData, returnQuery);
		if (wasInvoked || this.options.onAuthenticated) next.markAuthenticationCallbackInvoked();
		this.session.set(SessionData.STORE_KEY, next);
		if (this.options.onAuthenticated && !wasInvoked) this.options.onAuthenticated(this.user);
		this.tidyResponseData(returnQuery);
	}
	private tidyResponseData(returnQuery: string | null = null): void {
		const uri =
			returnQuery === null ? this.currentUriPath : this.currentUriPath.withQuery(returnQuery);
		this.redirectHandler.redirect(uri.withoutQueryValue(Authenticator.RESPONSE_QUERY_PARAMETER));
	}
}
