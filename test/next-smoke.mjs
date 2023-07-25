import assert from 'node:assert/strict';
import { CipherText, InitVector, decrypt } from '../dist/index.js';
const origin = process.env.AUTHWAVE_EXAMPLE_ORIGIN ?? 'http://127.0.0.1:3123';
const invoke = (path, cookie) =>
	fetch(origin + path, { headers: cookie ? { cookie } : {}, redirect: 'manual' });
const initial = await invoke('/login');
assert.equal(initial.status, 303);
const cookie = initial.headers.get('set-cookie').split(';')[0];
const query = new URL(initial.headers.get('location')).searchParams;
const plain = decrypt(
	query.get('c'),
	new InitVector().withBytes(Buffer.from(query.get('i'), 'base64')),
	's'.repeat(32),
);
const iv = plain.slice(plain.lastIndexOf('&secretIv=') + 10);
const cipher = String(
	new CipherText(
		'{"id":"next-smoke","email":"next@example.test"}',
		new InitVector().withBytes(Buffer.from(iv, 'base64')),
		's'.repeat(32),
	),
);
const callback = await invoke('/?AUTHWAVE_RESPONSE_DATA=' + encodeURIComponent(cipher), cookie);
assert.equal(callback.status, 303);
assert.deepEqual(await (await invoke('/', cookie)).json(), {
	id: 'next-smoke',
	email: 'next@example.test',
});
const logout = await invoke('/logout', cookie);
assert.equal(logout.status, 303);
assert.deepEqual(await (await invoke('/', cookie)).json(), { login: '/login' });
console.log('Built Next.js application: login, callback, restored user and logout passed');
