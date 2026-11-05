import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import express from 'express';
import expressSession from 'express-session';
import {
	Authenticator,
	SessionArrayWrapper,
	SessionData,
	Token,
	CipherText,
	RedirectSignal,
} from '../dist/index.js';
import { createNodeHandler, MemorySessionStore } from '../dist/node.js';
import { createExpressHandler } from '../dist/express.js';
import { createNextHandler } from '../dist/next.js';
const clientKey = 'deployment_' + 's'.repeat(32);
class MemorySession extends SessionArrayWrapper {
	regenerate() {}
}
const cases = [
	['//evil.example/path', '/path'],
	['//evil.example', '/'],
	['https://evil.example/path', '/path'],
	['https://user:pass@evil.example/path', '/path'],
	['https://app.example//evil.example/path', '/evil.example/path'],
	['/%2F%2Fevil.example/path', '/%2F%2Fevil.example/path'],
	['/members/a%2Fb', '/members/a%2Fb'],
	['/members/orders', '/members/orders'],
];
for (const [input, expected] of cases)
	test(`cleanup stays local: ${input}`, () => {
		const auth = new Authenticator({
			clientKey,
			currentUriPath: input + '?keep=%7e&flag&AUTHWAVE_RESPONSE_DATA=anything#details',
			session: new MemorySession({}),
			redirectHandler: {
				redirect(uri, code = 303) {
					assert.equal(code, 303);
					assert.equal(String(uri), expected + '?keep=%7e&flag#details');
					assert.equal(new URL(String(uri), 'https://app.example').origin, 'https://app.example');
				},
			},
		});
		assert.equal(auth.isLoggedIn(), false);
	});
for (const input of ['/\\evil.example/path', 'x:/\\evil.example/path'])
	test(`backslashes cannot change origin: ${input}`, () => {
		assert.throws(
			() =>
				new Authenticator({
					clientKey,
					currentUriPath: input + '?AUTHWAVE_RESPONSE_DATA=anything',
					session: new MemorySession({}),
				}),
			(error) => {
				assert.ok(error instanceof RedirectSignal);
				assert.equal(new URL(error.uri, 'https://app.example').origin, 'https://app.example');
				return true;
			},
		);
	});
test('authenticated cleanup preserves encoded paths and the saved query', () => {
	const token = new Token('s'.repeat(32));
	const session = new MemorySession({
		[SessionData.STORE_KEY]: new SessionData(token, null, 'filter=original&flag&encoded=%7e'),
	});
	const cipher = String(
		new CipherText(
			'{"id":"user-id","email":"person@example.com"}',
			token.getSecretIv(),
			's'.repeat(32),
		),
	);
	const auth = new Authenticator({
		clientKey,
		currentUriPath:
			'https://user:pass@evil.example//members/a%2Fb?AUTHWAVE_RESPONSE_DATA=' +
			encodeURIComponent(cipher) +
			'#details',
		session,
		redirectHandler: {
			redirect(uri) {
				assert.equal(String(uri), '/members/a%2Fb?filter=original&flag&encoded=%7e#details');
			},
		},
	});
	assert.equal(auth.getAuthUser().id, 'user-id');
});
test('cleanup removes duplicate response parameters without rewriting other values', () => {
	assert.throws(
		() =>
			new Authenticator({
				clientKey,
				currentUriPath:
					'//evil.example/path?AUTHWAVE_RESPONSE_DATA=one&flag&AUTHWAVE_RESPONSE_DATA=two&next=https://evil.example',
				session: new MemorySession({}),
			}),
		(error) => {
			assert.equal(error.uri, '/path?flag&next=https://evil.example');
			return error instanceof RedirectSignal;
		},
	);
});
for (const runtime of ['node', 'express', 'next'])
	test(`${runtime}: HTTP cleanup cannot redirect to another host`, async (t) => {
		let invoke;
		if (runtime === 'next') {
			const handler = createNextHandler(
				{ clientKey, store: new MemorySessionStore(), secureCookie: false },
				() => assert.fail('cleanup should redirect before the handler'),
			);
			invoke = () =>
				handler(
					new Request('http://localhost//evil.example/path?keep=1&AUTHWAVE_RESPONSE_DATA=anything'),
				);
		} else {
			let handler;
			if (runtime === 'node')
				handler = createNodeHandler(
					{ clientKey, store: new MemorySessionStore(), secureCookie: false },
					() => assert.fail('cleanup should redirect before the handler'),
				);
			else {
				const app = express();
				app.use(
					expressSession({
						secret: 'test signing secret',
						resave: false,
						saveUninitialized: false,
					}),
				);
				app.use(
					createExpressHandler({ clientKey }, () =>
						assert.fail('cleanup should redirect before the handler'),
					),
				);
				handler = app;
			}
			const server = createServer(handler);
			server.listen(0, '127.0.0.1');
			await once(server, 'listening');
			t.after(() => new Promise((resolve) => server.close(resolve)));
			invoke = () =>
				fetch(
					`http://127.0.0.1:${server.address().port}//evil.example/path?keep=1&AUTHWAVE_RESPONSE_DATA=anything`,
					{ redirect: 'manual' },
				);
		}
		const response = await invoke();
		assert.equal(response.status, 303);
		const location = response.headers.get('location');
		assert.equal(new URL(location, 'http://localhost').hostname, 'localhost');
		assert.equal(new URL(location, 'http://localhost').pathname, '/path');
		assert.equal(new URL(location, 'http://localhost').search, '?keep=1');
	});
