import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
	Authenticator,
	Token,
	SessionData,
	SessionArrayWrapper,
	UserResponseData,
	CipherText,
	RedirectSignal,
	NotLoggedInException,
	SessionRegenerationException,
} from '../dist/index.js';
import { openSession, MemorySessionStore } from '../dist/runtime.js';
import { createExpressHandler } from '../dist/express.js';
const secret = 's'.repeat(32),
	clientKey = 'deployment_' + secret;
function pending() {
	const token = new Token(secret);
	const data = { [SessionData.STORE_KEY]: new SessionData(token), basket: ['tea'] };
	const cipher = String(
		new CipherText('{"id":"user-id","email":"person@example.com"}', token.getSecretIv(), secret),
	);
	return { data, uri: '/callback?AUTHWAVE_RESPONSE_DATA=' + encodeURIComponent(cipher) };
}
test('core regenerates before storing identity or invoking the callback', () => {
	const { data, uri } = pending();
	const events = [];
	const session = new SessionArrayWrapper(data, () => {
		assert.throws(() => session.get(SessionData.STORE_KEY).getData(), NotLoggedInException);
		events.push('rotate');
	});
	assert.throws(
		() =>
			new Authenticator({
				clientKey,
				currentUriPath: uri,
				session,
				onAuthenticated: () => {
					assert.deepEqual(events, ['rotate']);
					events.push('callback');
				},
			}),
		RedirectSignal,
	);
	assert.deepEqual(events, ['rotate', 'callback']);
	assert.deepEqual(data.basket, ['tea']);
});
test('custom core containers must supply rotation, including for fake login', () => {
	const { data, uri } = pending();
	const session = new SessionArrayWrapper(data);
	let called = false;
	assert.throws(
		() =>
			new Authenticator({
				clientKey,
				currentUriPath: uri,
				session,
				onAuthenticated: () => {
					called = true;
				},
			}),
		SessionRegenerationException,
	);
	assert.equal(called, false);
	assert.throws(() => session.get(SessionData.STORE_KEY).getData(), NotLoggedInException);
	const fresh = {};
	const auth = new Authenticator({
		clientKey,
		currentUriPath: '/',
		session: new SessionArrayWrapper(fresh),
	});
	assert.throws(() => auth.fakeLogin('dev'), SessionRegenerationException);
	assert.deepEqual(fresh, {});
});
test('invalid responses and ordinary restoration do not rotate', () => {
	const { data } = pending();
	let rotations = 0;
	const session = new SessionArrayWrapper(data, () => {
		rotations++;
	});
	assert.throws(
		() => new Authenticator({ clientKey, currentUriPath: '/?AUTHWAVE_RESPONSE_DATA=bad', session }),
	);
	assert.equal(rotations, 0);
	const token = session.get(SessionData.STORE_KEY).getToken();
	session.set(SessionData.STORE_KEY, new SessionData(token, new UserResponseData('user', 'email')));
	assert.equal(new Authenticator({ clientKey, currentUriPath: '/', session }).isLoggedIn(), true);
	assert.equal(rotations, 0);
});
test('runtime invalidates the old ID before saving identity and keeps other values', async () => {
	const store = new MemorySessionStore();
	const { data, uri } = pending();
	const oldId = 'a'.repeat(64);
	await store.set(oldId, data, Date.now() + 60000);
	const events = [];
	const set = store.set.bind(store),
		del = store.delete.bind(store);
	store.delete = async (id) => {
		events.push('delete');
		await del(id);
	};
	store.set = async (id, value, expires) => {
		events.push('save');
		assert.equal(await store.get(oldId), undefined);
		await set(id, value, expires);
	};
	const context = await openSession('authwave.sid=' + oldId, { store });
	assert.throws(
		() => new Authenticator({ clientKey, currentUriPath: uri, session: context.session }),
		RedirectSignal,
	);
	assert.equal((await store.get(oldId))[SessionData.STORE_KEY].data, null);
	await context.commit();
	assert.deepEqual(events, ['delete', 'save']);
	const cookie = context.setCookie.split(';')[0];
	assert.notEqual(cookie, 'authwave.sid=' + oldId);
	const restored = await openSession(cookie, { store });
	assert.equal(
		new Authenticator({ clientKey, currentUriPath: '/', session: restored.session }).getAuthUser()
			.id,
		'user-id',
	);
	assert.deepEqual(restored.session.get('basket'), ['tea']);
	const replay = await openSession('authwave.sid=' + oldId, { store });
	assert.throws(
		() => new Authenticator({ clientKey, currentUriPath: uri, session: replay.session }),
		RedirectSignal,
	);
	assert.equal(replay.session.contains(SessionData.STORE_KEY), false);
});
test('failed invalidation prevents the runtime saving authenticated state', async () => {
	const { data, uri } = pending();
	let saves = 0;
	const store = {
		get: async () => JSON.parse(JSON.stringify(data)),
		delete: async () => {
			throw new Error('delete failed');
		},
		set: async () => {
			saves++;
		},
	};
	const context = await openSession('authwave.sid=' + 'a'.repeat(64), { store });
	assert.throws(
		() => new Authenticator({ clientKey, currentUriPath: uri, session: context.session }),
		RedirectSignal,
	);
	await assert.rejects(context.commit(), /delete failed/);
	assert.equal(saves, 0);
});
for (const fail of [false, true])
	test(`Express regenerates before persisting identity (failure=${fail})`, async () => {
		const { data, uri } = pending();
		const events = [];
		let callback = false;
		let result;
		const original = {
			...data,
			save(done) {
				events.push('save');
				done();
			},
			regenerate(done) {
				events.push('rotate');
				assert.throws(() => original[SessionData.STORE_KEY].getData(), NotLoggedInException);
				if (fail) {
					done(new Error('rotation failed'));
					return;
				}
				req.session = { save: original.save, regenerate: original.regenerate };
				done();
			},
		};
		const req = { originalUrl: uri, session: original };
		await createExpressHandler(
			{
				clientKey,
				onAuthenticated: () => {
					callback = true;
					assert.equal(req.session[SessionData.STORE_KEY].getData().getId(), 'user-id');
				},
			},
			() => assert.fail('callback should redirect'),
		)(
			req,
			{
				setHeader() {},
				redirect() {
					result = 'redirect';
				},
				send() {},
			},
			(error) => {
				result = error;
			},
		);
		if (fail) {
			assert.match(result.message, /rotation failed/);
			assert.equal(callback, false);
			assert.throws(() => original[SessionData.STORE_KEY].getData(), NotLoggedInException);
		} else {
			assert.equal(result, 'redirect');
			assert.equal(callback, true);
			assert.deepEqual(req.session.basket, ['tea']);
			assert.deepEqual(events, ['rotate', 'save']);
		}
	});
