# Running the examples

From the repository root, run `npm ci && npm run build`. All examples require `AUTHWAVE_CLIENT_KEY` with the complete provider-issued key. Configure the provider's client return URI to the example's origin, normally `http://localhost:3000/`.

- Node.js: `node examples/node.mjs`.
- Express: also set an independent strong `SESSION_SECRET`, then run `node examples/express.mjs`.
- Next.js: `npx next dev examples/next`; or `npm run build:example:next` then `npx next start examples/next`.

Visit `/login`, complete sign-in, inspect `/`, then visit `/logout`. Each example handles return requests before producing output. The JSON result avoids HTML escaping issues.

`next-route.ts` is a TypeScript version for copying into an existing App Router project. Use explicit callback routes if your application already defines a home page.

These examples use development memory sessions and local HTTP cookies. Production needs persistent shared server-side storage, HTTPS, secure cookies, and appropriate proxy/session configuration. Never expose fake-login routes in production. See the sibling wiki for the session store contract and authentication callback behavior.
