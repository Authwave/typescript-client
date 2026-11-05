import test from 'node:test';
import assert from 'node:assert/strict';
import { AdminUri, InsecureProtocolException } from '../dist/index.js';

const cases = [
	['http://login.realtest.authwave.test:9090', true],
	['http://app.test', true],
	['http://LOGIN.EXAMPLE.TEST:9090', true],
	['http://login.example.test.:9090', true],
	['http://localhost:9090', true],
	['http://127.0.0.127:9090', true],
	['https://login.authwave.com', true],
	['http://login.realtest.authwave-test:9090', false],
	['http://example.test.attacker.com', false],
	['http://exampletest', false],
	['http://test', false],
	['http://login.authwave.com', false],
	['ftp://example.test', false],
];
for (const [host, allowed] of cases) {
	test(`provider protocol: ${host}`, () => {
		if (!allowed) {
			assert.throws(() => new AdminUri(host), InsecureProtocolException);
			return;
		}
		const uri = new AdminUri(host);
		assert.equal(uri.getPath(), '/admin/');
		if (host.startsWith('http://')) assert.equal(uri.getScheme(), 'http');
		if (host.includes(':9090')) assert.equal(uri.getPort(), 9090);
	});
}
