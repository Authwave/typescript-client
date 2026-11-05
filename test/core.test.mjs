import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as A from '../dist/index.js';
const secret = 's'.repeat(32),
	key = 'deployment_' + secret;
const record = () => ({
	destinations: [],
	redirect(uri, code = 303) {
		this.destinations.push([String(uri), code]);
	},
});
const setup = (data = {}, uri = '/', extra = {}) => {
	const redirect = record(),
		session = new A.SessionArrayWrapper(data);
	return {
		auth: new A.Authenticator({
			clientKey: key,
			currentUriPath: uri,
			session,
			redirectHandler: redirect,
			...extra,
		}),
		session,
		redirect,
		data,
	};
};
test('user and response data accessors, readonly properties, legacy subclass', () => {
	for (const user of [new A.AuthUser('id', 'email'), new A.User('id', 'email')]) {
		assert.throws(() => (user.id = 'other'), TypeError);
		assert.ok(user instanceof A.AuthUser);
	}
	const d = new A.UserResponseData('id', 'email', 'Welcome');
	assert.equal(d.getId(), 'id');
	assert.equal(d.getEmail(), 'email');
	assert.equal(d.getMessage(), 'Welcome');
});
test('exceptions inherit AuthwaveException; absent session/token/data/user', () => {
	for (const name of [
		'SessionNotStartedException',
		'NotLoggedInException',
		'InsecureProtocolException',
		'InvalidUserDataSerializationException',
		'ResponseCipherDecryptionException',
	])
		assert.ok(new A[name]() instanceof A.AuthwaveException);
	assert.throws(
		() => new A.Authenticator({ clientKey: key, currentUriPath: '/' }),
		A.SessionNotStartedException,
	);
	assert.throws(() => new A.SessionData().getToken(), A.NotLoggedInException);
	assert.throws(() => new A.SessionData().getData(), A.NotLoggedInException);
	const { auth } = setup();
	assert.equal(auth.isLoggedIn(), false);
	assert.throws(() => auth.getAuthUser(), A.NotLoggedInException);
	assert.throws(() => auth.getUser(), A.NotLoggedInException);
});
test('tokens are random, deterministic per token, supplied IV identities preserved', () => {
	const sessionIv = new A.InitVector(),
		iv = new A.InitVector();
	const token = new A.Token(secret, sessionIv, iv);
	assert.equal(token.getIv(), iv);
	assert.equal(token.getSecretIv(), sessionIv);
	assert.equal(
		String(token.generateRequestCipher('action=login')),
		String(token.generateRequestCipher('action=login')),
	);
	assert.notEqual(
		String(token.generateRequestCipher('action=login')),
		String(new A.Token(secret).generateRequestCipher('action=login')),
	);
	assert.equal(
		A.decrypt(String(token.generateRequestCipher('action=login')), iv, secret),
		`action=login&secretIv=${sessionIv}`,
	);
	assert.throws(() => new A.InitVector(0), RangeError);
	assert.throws(() => new A.Token('').generateRequestCipher(), A.EncryptionFailureException);
});
test('low-level decode uses request IV, validates JSON and identity types', () => {
	const token = new A.Token(secret);
	const encrypt = (value) => String(new A.CipherText(value, token.getIv(), secret));
	for (const idName of ['uuid', 'id']) {
		const d = token.decode(encrypt(JSON.stringify({ [idName]: 'id', email: 'email' })));
		assert.equal(d.getId(), 'id');
		assert.equal(d.getEmail(), 'email');
	}
	for (const value of [
		'bad-json',
		'null',
		'[]',
		'{}',
		JSON.stringify({ id: 123, email: 'email' }),
		JSON.stringify({ id: 'id', email: 2 }),
	])
		assert.throws(() => token.decode(encrypt(value)), A.InvalidUserDataSerializationException);
	assert.throws(() => token.decode('bad cipher'), A.DecryptionFailureException);
	const valid = encrypt('{"id":"id","email":"email"}');
	const bytes = Buffer.from(valid, 'base64');
	bytes[0] ^= 1;
	assert.throws(() => token.decode(bytes.toString('base64')), A.DecryptionFailureException);
});
test('session serialization restores token, data, query and callback marker', () => {
	const token = new A.Token(secret);
	const d = new A.SessionData(
		token,
		new A.UserResponseData('id', 'email', 'Welcome'),
		'x=%7e&flag',
	);
	assert.equal(d.getToken(), token);
	assert.equal(d.hasInvokedAuthenticationCallback(), false);
	d.markAuthenticationCallbackInvoked();
	const session = new A.SessionArrayWrapper(
		JSON.parse(JSON.stringify({ [A.SessionData.STORE_KEY]: d })),
	);
	assert.equal(session.contains(A.SessionData.STORE_KEY), true);
	const restored = session.get(A.SessionData.STORE_KEY);
	assert.equal(restored.hasInvokedAuthenticationCallback(), true);
	assert.equal(restored.getReturnQuery(), 'x=%7e&flag');
	assert.equal(restored.getData().getMessage(), 'Welcome');
	assert.equal(
		String(restored.getToken().generateRequestCipher()),
		String(token.generateRequestCipher()),
	);
	session.remove(A.SessionData.STORE_KEY);
	assert.equal(session.contains(A.SessionData.STORE_KEY), false);
	const empty = A.SessionData.fromJSON(JSON.parse(JSON.stringify(new A.SessionData())));
	assert.throws(() => empty.getData(), A.NotLoggedInException);
});
test('callback runs after storage, at most once after exception and across restoration', () => {
	const token = new A.Token(secret),
		state = { [A.SessionData.STORE_KEY]: new A.SessionData(token, null, 'tab=orders') };
	let calls = 0;
	const response = String(
		new A.CipherText('{"id":"user","email":"person@example.com"}', token.getSecretIv(), secret),
	);
	const uri = '/?AUTHWAVE_RESPONSE_DATA=' + encodeURIComponent(response);
	assert.throws(
		() =>
			setup(state, uri, {
				onAuthenticated: () => {
					calls++;
					assert.equal(state[A.SessionData.STORE_KEY].hasInvokedAuthenticationCallback(), true);
					throw new Error('app failed');
				},
			}),
		/app failed/,
	);
	const { auth, redirect } = setup(JSON.parse(JSON.stringify(state)), uri, {
		onAuthenticated: () => calls++,
	});
	assert.equal(calls, 1);
	assert.equal(auth.getAuthUser().id, 'user');
	assert.equal(redirect.destinations[0][0], '/?tab=orders');
	setup(state, '/', { onAuthenticated: () => calls++ });
	assert.equal(calls, 1);
});
test('response preserves raw base64 plus and saved query bytes, cleans unsolicited response', () => {
	const token = new A.Token(secret);
	let response;
	let i = 0;
	do {
		response = String(
			new A.CipherText(
				JSON.stringify({ id: String(i++), email: 'person@example.com' }),
				token.getSecretIv(),
				secret,
			),
		);
	} while (!response.includes('+'));
	const state = {
		[A.SessionData.STORE_KEY]: new A.SessionData(token, null, 'flag&encoded=%7e&x=1'),
	};
	const { auth, redirect } = setup(state, '/page?AUTHWAVE_RESPONSE_DATA=' + response + '#details');
	assert.equal(auth.isLoggedIn(), true);
	assert.equal(redirect.destinations[0][0], '/page?flag&encoded=%7e&x=1#details');
	const other = setup({}, '/page?x=1&AUTHWAVE_RESPONSE_DATA=untrusted#details');
	assert.equal(other.auth.isLoggedIn(), false);
	assert.equal(other.redirect.destinations[0][0], '/page?x=1#details');
	assert.throws(
		() =>
			setup(
				{ [A.SessionData.STORE_KEY]: new A.SessionData(token) },
				'/?AUTHWAVE_RESPONSE_DATA=bad',
			),
		A.DecryptionFailureException,
	);
});
test('fake login stores data, emits decryptable response, defers current user and local logout', () => {
	const { auth, session, redirect, data } = setup({}, '/current?old=1');
	auth.fakeLogin('dev');
	assert.equal(auth.isLoggedIn(), false);
	const destination = redirect.destinations[0][0];
	assert.ok(destination.startsWith('/?AUTHWAVE_RESPONSE_DATA='));
	assert.equal(
		session.get(A.SessionData.STORE_KEY).getData().getEmail(),
		A.Authenticator.FAKE_EMAIL,
	);
	const next = setup(JSON.parse(JSON.stringify(data)), destination);
	assert.equal(next.auth.getAuthUser().id, 'dev');
	next.auth.logout();
	assert.equal(next.auth.isLoggedIn(), false);
	assert.equal(next.redirect.destinations.length, 1);
	const custom = setup();
	custom.auth.fakeLogin('dev', 'dev@example.com', '/members');
	const next2 = setup(custom.data, custom.redirect.destinations[0][0]);
	next2.auth.logout('/bye');
	assert.equal(next2.redirect.destinations.length, 2);
});
test('default redirect stops execution, default login/logout tokens, URI objects and admin', () => {
	const session = new A.SessionArrayWrapper({});
	const auth = new A.Authenticator({
		clientKey: key,
		currentUriPath: new URL('https://app.example.com/path'),
		session,
	});
	assert.throws(
		() => auth.login(),
		(e) => e instanceof A.RedirectSignal && e.code === 303,
	);
	assert.ok(session.get(A.SessionData.STORE_KEY).getToken() instanceof A.Token);
	assert.throws(() => auth.logout(), A.RedirectSignal);
	assert.equal(session.contains(A.SessionData.STORE_KEY), false);
	assert.equal(String(auth.getAdminUri()), 'https://login.authwave.com/admin/');
	assert.equal(auth.getAdminUri().getPath(), '/admin/');
	const { auth: a } = setup();
	a.setReturnUri('/return');
	const uri = a.getLoginUri(new A.Token(secret));
	assert.equal(
		Buffer.from(new URLSearchParams(uri.getQuery()).get('u'), 'hex').toString(),
		'/return',
	);
});
