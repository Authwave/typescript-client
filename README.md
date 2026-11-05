TypeScript client library to implement Authwave in your application
=================================================================

Authwave is an open source identity provider that can be self-hosted. This server-side client connects JavaScript and TypeScript applications to a provider, using the PHP client as its behavioral and wire-protocol reference.

Includes Node.js, Express, and Next.js App Router integrations. Requires Node.js 22+. ESM with TypeScript declarations. Keep the client key on the server.

Basic usage
-----------

```javascript
import { createServer } from 'node:http';
import { createNodeHandler, MemorySessionStore } from '@authwave/typescript-client/node';

const clientKey = process.env.AUTHWAVE_CLIENT_KEY;
if (!clientKey) throw new Error('Set AUTHWAVE_CLIENT_KEY');

createServer(createNodeHandler({
  clientKey,
  store: new MemorySessionStore(), // development only
  secureCookie: false, // local HTTP only; defaults to true
}, (auth, req) => {
  const path = new URL(req.url, 'http://localhost:3000').pathname;
  if (path === '/login') { auth.setReturnUri('/'); auth.login(); }
  if (path === '/logout') auth.logout('/');
  return JSON.stringify(auth.isLoggedIn()
    ? { id: auth.getAuthUser().id, email: auth.getAuthUser().email }
    : { login: '/login' });
})).listen(3000);
```

Register the application with your provider and configure its client return URI. The key consists of a deployment ID and a raw 32-byte secret, separated at the final underscore. `authwaveHost` defaults to `login.authwave.com`.

Install and build this local repository with `npm ci && npm run build`. From your application, run `npm install /absolute/path/to/typescript-client`. This creates the local package dependency; no npm publication is implied.

A token can encrypt only its first complete request. Repeating the same request is allowed; a different payload raises TokenReuseException. Create a fresh token for a different action or return query, and do not copy tokens or reuse supplied IVs. Session serialisation retains the binding. Tokens restored from older sessions without a binding can still decrypt responses, but require a fresh token to start another request.

Runtime integrations
--------------------

- `@authwave/typescript-client/node`: `createNodeHandler(options, handler)` with a server-side `SessionStore`.
- `@authwave/typescript-client/express`: `createExpressHandler(options, handler)`, mounted after `express-session`.
- `@authwave/typescript-client/next`: `createNextHandler(options, handler)` exported from a Node.js App Router Route Handler.

Handlers receive an `Authenticator` and the request. Node handlers return a string/Buffer, Express handlers return a response body, and Next.js handlers return a `Response`. Promises for these results are supported. Adapters persist session changes before responding or redirecting. `onAuthenticated` is synchronous and runs at most once per exchange under sequential session processing.

See [working examples](examples) and the sibling [wiki](../typescript-client.wiki/Home.md), particularly its [Quick start guide](../typescript-client.wiki/Quick-start-guide.md). Production deployments need HTTPS and shared persistent session storage. `MemorySessionStore` is for local development. Never expose serialized session records, which contain token secrets, to the browser.

Running tests
-------------

```bash
npm ci
npm run typecheck
npm test
```

The suite includes direct comparisons against the sibling PHP implementation, including byte-identical encrypted requests. PHP with Sodium and the PHP client's installed Composer dependencies are required. Set `AUTHWAVE_PHP_REFERENCE` to override the default `../php-client` path. Run just these comparisons using `npm run test:parity`.

[PARITY.md](PARITY.md) maps every PHP source class and documents the runtime adaptations. Automated tests simulate provider responses; browser validation against your deployed provider remains a deployment check.
