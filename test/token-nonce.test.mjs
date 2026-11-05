import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
	Authenticator,
	Token,
	TokenReuseException,
	SessionArrayWrapper,
	SessionData,
	CipherText,
	EncryptionFailureException,
	LoginUri,
	LogoutUri,
	decrypt,
} from '../dist/index.js';
const secret = 's'.repeat(32),
	clientKey = 'deployment_' + secret;
for (const [first, second] of [
	['action=login', 'action=logout'],
	['', 'action=login'],
	['action=login', ''],
	['action=login&returnQuery=page%3D1', 'action=login&returnQuery=page%3D2'],
])
	test(`reject changed token payload: ${first} -> ${second}`, () => {
		const token = new Token(secret);
		const iv = token.getIv().getBytes();
		const cipher = String(token.generateRequestCipher(first));
		assert.throws(() => token.generateRequestCipher(second), TokenReuseException);
		assert.deepEqual(token.getIv().getBytes(), iv);
		assert.equal(String(token.generateRequestCipher(first)), cipher);
		assert.equal(
			decrypt(cipher, token.getIv(), secret),
			first + '&secretIv=' + token.getSecretIv(),
		);
	});
test('session serialisation preserves the request binding', () => {
	const token = new Token(secret),
		cipher = String(token.generateRequestCipher('action=login'));
	const restored = SessionData.fromJSON(
		JSON.parse(JSON.stringify(new SessionData(token))),
	).getToken();
	assert.equal(String(restored.generateRequestCipher('action=login')), cipher);
	assert.throws(() => restored.generateRequestCipher('action=logout'), TokenReuseException);
});
test('unused tokens can be restored before first encryption', () => {
	const token = Token.fromJSON(JSON.parse(JSON.stringify(new Token(secret))));
	assert.ok(String(token.generateRequestCipher('action=login')));
});
test('legacy tokens can decrypt but cannot reuse an unknown request nonce', () => {
	const token = new Token(secret),
		legacy = token.toJSON();
	delete legacy.requestPlaintext;
	const cipher = String(
		new CipherText('{"id":"user-id","email":"person@example.com"}', token.getIv(), secret),
	);
	const restored = Token.fromJSON(legacy);
	assert.equal(restored.decode(cipher).getId(), 'user-id');
	assert.throws(() => restored.generateRequestCipher('action=login'), TokenReuseException);
});
test('failed encryption does not bind the token', () => {
	const token = new Token('');
	for (const message of ['action=login', 'action=logout'])
		assert.throws(() => token.generateRequestCipher(message), EncryptionFailureException);
});
test('login and logout URI builders cannot share a token', () => {
	const token = new Token(secret);
	const login = new LoginUri(token, '/callback', 'deployment');
	assert.equal(String(new LoginUri(token, '/callback', 'deployment')), String(login));
	assert.throws(() => new LogoutUri(token, '/callback', 'deployment'), TokenReuseException);
	assert.ok(String(new LogoutUri(new Token(secret), '/callback', 'deployment')));
});
test('a rejected login preserves the existing exchange', () => {
	const pending = new SessionData(new Token(secret));
	const state = { [SessionData.STORE_KEY]: pending, basket: ['tea'] };
	const auth = new Authenticator({
		clientKey,
		currentUriPath: '/callback',
		session: new SessionArrayWrapper(state),
	});
	const used = new Token(secret);
	used.generateRequestCipher('action=logout');
	assert.throws(() => auth.login(used), TokenReuseException);
	assert.equal(state[SessionData.STORE_KEY], pending);
	assert.deepEqual(state.basket, ['tea']);
});
test('login saves the bound token for later requests', () => {
	const state = {},
		session = new SessionArrayWrapper(state),
		token = new Token(secret);
	const auth = new Authenticator({
		clientKey,
		currentUriPath: '/callback',
		session,
		redirectHandler: { redirect() {} },
	});
	auth.login(token);
	const restored = new SessionArrayWrapper(JSON.parse(JSON.stringify(state)))
		.get(SessionData.STORE_KEY)
		.getToken();
	assert.throws(() => restored.generateRequestCipher('action=logout'), TokenReuseException);
});
