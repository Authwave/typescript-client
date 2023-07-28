import { createServer } from 'node:http';
import { createNodeHandler, MemorySessionStore } from '@authwave/typescript-client/node';

const clientKey = process.env.AUTHWAVE_CLIENT_KEY;
if (!clientKey) throw new Error('Set AUTHWAVE_CLIENT_KEY');
const store = new MemorySessionStore(); // local development only
const handle = createNodeHandler({ clientKey, store, secureCookie: false }, (auth, req) => {
	const path = new URL(req.url, 'http://localhost:3000').pathname;
	if (path === '/login') {
		auth.setReturnUri('/');
		auth.login();
	}
	if (path === '/logout') {
		auth.logout('/');
	}
	return JSON.stringify(
		auth.isLoggedIn()
			? { id: auth.getAuthUser().id, email: auth.getAuthUser().email }
			: { login: '/login' },
	);
});
createServer(handle).listen(3000);
