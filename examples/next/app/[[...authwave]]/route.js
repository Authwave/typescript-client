import { createNextHandler, MemorySessionStore } from '@authwave/typescript-client/next';
export const runtime = 'nodejs';
const clientKey = process.env.AUTHWAVE_CLIENT_KEY;
if (!clientKey) throw new Error('Set AUTHWAVE_CLIENT_KEY');
const store = new MemorySessionStore(); // local development only
export const GET = createNextHandler({ clientKey, store, secureCookie: false }, (auth, request) => {
	const path = new URL(request.url).pathname;
	if (path === '/login') {
		auth.setReturnUri('/');
		auth.login();
	}
	if (path === '/logout') auth.logout('/');
	return Response.json(
		auth.isLoggedIn()
			? { id: auth.getAuthUser().id, email: auth.getAuthUser().email }
			: { login: '/login' },
	);
});
