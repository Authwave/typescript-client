import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import express from 'express';
import expressSession from 'express-session';
import { NextRequest, NextResponse } from 'next/server.js';
import { createNodeHandler, MemorySessionStore } from '../dist/node.js';
import { createExpressHandler } from '../dist/express.js';
import { createNextHandler } from '../dist/next.js';
import { CipherText, InitVector, decrypt, SessionData } from '../dist/index.js';
const secret = 's'.repeat(32),
	clientKey = 'deployment_' + secret;
function simulateProvider(location) {
	const query = new URL(location).searchParams;
	const plain = decrypt(
		query.get('c'),
		new InitVector().withBytes(Buffer.from(query.get('i'), 'base64')),
		secret,
	);
	// secretIv is deliberately unescaped in PHP's encrypted plaintext.
	const iv = plain.slice(plain.lastIndexOf('&secretIv=') + 10);
	const cipher = String(
		new CipherText(
			'{"id":"user-id","email":"person@example.com"}',
			new InitVector().withBytes(Buffer.from(iv, 'base64')),
			secret,
		),
	);
	return '/callback?AUTHWAVE_RESPONSE_DATA=' + encodeURIComponent(cipher);
}
const action = (auth, path) => {
	if (path === '/login') {
		auth.setReturnUri('/callback');
		auth.login();
	}
	if (path === '/logout') auth.logout('/signed-out');
	return { loggedIn: auth.isLoggedIn(), id: auth.isLoggedIn() ? auth.getAuthUser().id : null };
};
for (const runtime of ['node', 'express', 'next'])
	test(`${runtime}: HTTP login, provider callback, restore, isolation, logout`, async (t) => {
		let server;
		let origin = 'http://localhost';
		let invoke;
		if (runtime === 'next') {
			const handler = createNextHandler(
				{ clientKey, store: new MemorySessionStore(), secureCookie: false },
				(auth, request) => NextResponse.json(action(auth, new URL(request.url).pathname)),
			);
			invoke = (path, cookie) =>
				handler(new NextRequest(origin + path, { headers: cookie ? { cookie } : {} }));
		} else {
			let handler;
			if (runtime === 'node')
				handler = createNodeHandler(
					{ clientKey, store: new MemorySessionStore(), secureCookie: false },
					(auth, req) => JSON.stringify(action(auth, new URL(req.url, origin).pathname)),
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
					createExpressHandler({ clientKey }, (auth, req) =>
						action(auth, new URL(req.originalUrl, origin).pathname),
					),
				);
				handler = app;
			}
			server = createServer(handler);
			server.listen(0, '127.0.0.1');
			await once(server, 'listening');
			t.after(() => new Promise((r) => server.close(r)));
			origin = `http://127.0.0.1:${server.address().port}`;
			invoke = (path, cookie) =>
				fetch(origin + path, { headers: cookie ? { cookie } : {}, redirect: 'manual' });
		}
		const first = await invoke('/login');
		assert.equal(first.status, 303);
		const cookie = first.headers.get('set-cookie').split(';')[0];
		assert.ok(cookie);
		const callback = simulateProvider(first.headers.get('location'));
		const completed = await invoke(callback, cookie);
		assert.equal(completed.status, 303);
		assert.equal(new URL(completed.headers.get('location'), origin).pathname, '/callback');
		const restored = await invoke('/callback', cookie);
		assert.deepEqual(await restored.json(), { loggedIn: true, id: 'user-id' });
		assert.equal(restored.headers.get('cache-control'), 'no-store');
		const outsider = await invoke('/callback');
		assert.equal((await outsider.json()).loggedIn, false);
		const logout = await invoke('/logout', cookie);
		assert.equal(logout.status, 303);
		assert.equal(new URL(logout.headers.get('location')).hostname, 'login.authwave.com');
		const after = await invoke('/signed-out', cookie);
		assert.equal((await after.json()).loggedIn, false);
	});
test('Next saves callback marker on application failure; no replay invocation', async () => {
	const store = new MemorySessionStore();
	let calls = 0;
	const handler = createNextHandler(
		{
			clientKey,
			store,
			secureCookie: false,
			onAuthenticated: () => {
				calls++;
				throw new Error('app failed');
			},
		},
		(auth, req) => {
			if (new URL(req.url).pathname === '/login') auth.login();
			return Response.json({ loggedIn: auth.isLoggedIn() });
		},
	);
	const initial = await handler(new Request('http://localhost/login'));
	const cookie = initial.headers.get('set-cookie').split(';')[0];
	const callback = simulateProvider(initial.headers.get('location'));
	await assert.rejects(
		handler(new Request('http://localhost' + callback, { headers: { cookie } })),
		/app failed/,
	);
	assert.equal(calls, 1);
	const repeated = await handler(
		new Request('http://localhost' + callback, { headers: { cookie } }),
	);
	assert.equal(repeated.status, 303);
	assert.equal(calls, 1);
});
test('store failures prevent redirects; Express missing session reaches next', async () => {
	const handler = createNextHandler(
		{
			clientKey,
			store: {
				get: async () => undefined,
				set: async () => {
					throw new Error('store failed');
				},
			},
		},
		(auth) => {
			auth.login();
			return new Response();
		},
	);
	await assert.rejects(handler(new Request('https://app.example/login')), /store failed/);
	let error;
	await createExpressHandler({ clientKey }, () => ({}))(
		{ originalUrl: '/' },
		{},
		(e) => (error = e),
	);
	assert.equal(error.name, 'SessionNotStartedException');
});
test('Next cookies are opaque, secure by default, unknown IDs replaced; expiry', async () => {
	const store = new MemorySessionStore();
	const handler = createNextHandler({ clientKey, store }, () => new Response('ok'));
	const result = await handler(
		new Request('https://app.example/', { headers: { cookie: 'authwave.sid=' + 'f'.repeat(64) } }),
	);
	const cookie = result.headers.get('set-cookie');
	assert.ok(cookie.includes('HttpOnly; SameSite=Lax'));
	assert.ok(cookie.endsWith('; Secure'));
	assert.ok(!cookie.includes(secret));
	assert.ok(!cookie.startsWith('authwave.sid=' + 'f'.repeat(64)));
	await store.set('expired', {}, Date.now() - 1);
	assert.equal(await store.get('expired'), undefined);
});
