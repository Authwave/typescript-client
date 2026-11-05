import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
	Authenticator,
	Token,
	InitVector,
	SessionData,
	SessionArrayWrapper,
	UserResponseData,
	CipherText,
} from '../dist/index.js';
const secret = 's'.repeat(32);
const cases = [
	{},
	{ uri: '/ordinary?filter=x' },
	{ state: 'pending' },
	{ state: 'user' },
	{ uri: '/?AUTHWAVE_RESPONSE_DATA=untrusted' },
	...['login', 'logout'].flatMap((action) =>
		['', 'pending', 'user'].flatMap((state) => [
			{ action, state },
			{ action, state, returnUri: '/members?x=1#latest' },
			{ action, state, host: 'http://localhost:8081' },
			{ action, state, host: 'http://unsafe.example' },
			{ action, state, host: 'http://127.0.0.127:8080' },
			{ action, state, host: 'http://127.0.0.1' },
		]),
	),
	...[null, '/configured?source=authwave'].flatMap((returnUri) =>
		[null, '/explicit', '?signed-out=1', 'https://example.com/bye'].map((redirectTo) => ({
			action: 'logout',
			state: 'user',
			returnUri,
			redirectTo,
		})),
	),
	{ action: 'logout', state: 'user', email: Authenticator.FAKE_EMAIL },
	...[false, true].flatMap((callback) =>
		[false, true].flatMap((rawPlus) =>
			[null, '', 'filter=original&flag&encoded=%7e#no'].map((returnQuery) => ({
				state: 'pending',
				uri: '/my-page?filter=changed',
				response: { id: 'user-id', email: 'person@example.com' },
				callback,
				rawPlus,
				returnQuery,
			})),
		),
	),
	...[{}, { id: null, email: 'email' }, { id: false, email: 'email' }].map((response) => ({
		state: 'pending',
		response,
	})),
	{ state: 'pending', response: { id: 123, email: 'person@example.com' }, callback: true },
	{
		state: 'pending',
		response: { id: 'user-id', email: 'person@example.com' },
		callback: true,
		throwCallback: true,
	},
];
const php = spawnSync(
	'php',
	[
		fileURLToPath(new URL('./php-oracle.php', import.meta.url)),
		process.env.AUTHWAVE_PHP_REFERENCE ??
			fileURLToPath(new URL('../../php-client', import.meta.url)),
	],
	{ input: JSON.stringify(cases), encoding: 'utf8', timeout: 10000 },
);
if (php.status !== 0 || !php.stdout)
	throw new Error(
		`PHP parity oracle failed: ${php.error?.message ?? ''} ${php.stderr || php.stdout}`,
	);
const expected = JSON.parse(php.stdout);
for (const [i, c] of cases.entries())
	test(`PHP differential ${i}: ${JSON.stringify(c)}`, () => {
		const token = new Token(
			secret,
			new InitVector().withBytes(Buffer.from('a'.repeat(24))),
			new InitVector().withBytes(Buffer.from('f'.repeat(24))),
		);
		const state = { basket: ['tea'] };
		const session = new SessionArrayWrapper(state, () => {});
		const redirects = [];
		let calls = 0;
		if (c.state === 'pending')
			session.set(SessionData.STORE_KEY, new SessionData(token, null, c.returnQuery ?? null));
		if (c.state === 'user')
			session.set(
				SessionData.STORE_KEY,
				new SessionData(token, new UserResponseData('user-id', c.email ?? 'person@example.com')),
			);
		let uri = c.uri ?? '/account?tab=security';
		if (c.response) {
			const cipher = String(
				new CipherText(JSON.stringify(c.response), token.getSecretIv(), secret),
			);
			// Insert before the fragment, as PHP concatenation does (a fragment intentionally swallows it).
			uri +=
				(uri.includes('?') ? '&' : '?') +
				'AUTHWAVE_RESPONSE_DATA=' +
				(c.rawPlus ? cipher : encodeURIComponent(cipher));
		}
		let auth = null,
			error = null;
		try {
			auth = new Authenticator({
				clientKey: 'deployment_with_underscores_' + secret,
				currentUriPath: uri,
				authwaveHost: c.host,
				session,
				redirectHandler: { redirect: (u, code = 303) => redirects.push([String(u), code]) },
				onAuthenticated: c.callback
					? () => {
							calls++;
							if (c.throwCallback) throw new Error('callback');
						}
					: undefined,
			});
			if (c.returnUri != null) auth.setReturnUri(c.returnUri);
			if (c.action === 'login') auth.login(token);
			if (c.action === 'logout') auth.logout(c.redirectTo ?? null, token);
		} catch (e) {
			error = e.message === 'callback' ? 'RuntimeException' : e.name;
		}
		const stored = session.get(SessionData.STORE_KEY);
		let data = null;
		if (stored) {
			try {
				const d = stored.getData();
				data = [d.getId(), d.getEmail()];
			} catch {}
		}
		const u = auth?.isLoggedIn() ? auth.getAuthUser() : null;
		assert.deepEqual(
			{
				redirects,
				calls,
				error,
				user: u ? [u.id, u.email] : null,
				stored: !!stored,
				data,
				returnQuery: stored?.getReturnQuery() ?? null,
				invoked: stored?.hasInvokedAuthenticationCallback() ?? null,
				basket: state.basket,
			},
			expected[i],
		);
	});
