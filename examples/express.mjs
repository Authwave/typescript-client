if (!process.env.AUTHWAVE_CLIENT_KEY || !process.env.SESSION_SECRET)
	throw new Error('Set AUTHWAVE_CLIENT_KEY and SESSION_SECRET');
import express from 'express';
import session from 'express-session';
import { createExpressHandler } from '@authwave/typescript-client/express';

const app = express();
app.use(
	session({
		secret: process.env.SESSION_SECRET, // independent session-signing secret
		resave: false,
		saveUninitialized: false,
		cookie: { httpOnly: true, sameSite: 'lax', secure: false }, // local HTTP only
	}),
);
app.use(
	createExpressHandler({ clientKey: process.env.AUTHWAVE_CLIENT_KEY }, (auth, req) => {
		const path = new URL(req.originalUrl, 'http://localhost:3000').pathname;
		if (path === '/login') {
			auth.setReturnUri('/');
			auth.login();
		}
		if (path === '/logout') auth.logout('/');
		return auth.isLoggedIn()
			? { id: auth.getAuthUser().id, email: auth.getAuthUser().email }
			: { login: '/login' };
	}),
);
app.listen(3000);
