import express from 'express';
import session from 'express-session';
import { createServer } from 'node:http';
import { createExpressHandler } from '../dist/express.js';
import { createNodeHandler, MemorySessionStore } from '../dist/node.js';
import { createNextHandler } from '../dist/next.js';
import type { NextRequest } from 'next/server.js';
const app = express();
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
app.use(
	createExpressHandler({ clientKey: 'key' }, (auth, req) => ({
		loggedIn: auth.isLoggedIn(),
		path: req.originalUrl,
	})),
);
createServer(createNodeHandler({ clientKey: 'key', store: new MemorySessionStore() }, () => 'ok'));
const GET: (req: NextRequest) => Promise<Response> = createNextHandler(
	{ clientKey: 'key', store: new MemorySessionStore() },
	() => Response.json({ ok: true }),
);
void GET;
