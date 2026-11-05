# PHP reference parity

Reference: `Authwave/php-client` commit `72c213ddef1797cd096757e1c8c70d826abd7514`. Every source class is represented below. Parity means equivalent client features and wire behavior, with the runtime adaptations described here; it is not a claim that PHP and JavaScript have identical type systems or every inherited PSR-7 URI operation.

| PHP source | TypeScript source / export | Validation |
| --- | --- | --- |
| `Authenticator.php` | `src/authenticator.ts`: `Authenticator` | Login, restore, callback response, cleanup, saved queries, destination overrides, logout, fake login, deprecated getter |
| `AuthUser.php` | `src/user.ts`: `AuthUser` | Read-only ID and email properties |
| `User.php` | `src/user.ts`: `User` | Deprecated subclass and getter identity |
| `Token.php` | `src/token.ts`: `Token` | Supplied/random IVs, deterministic cipher, decode validation, JSON persistence |
| `SessionData.php` | `src/session.ts`: `SessionData` | Absent token/data, return query, callback marker, JSON round trip |
| `GlobalSessionContainer.php` | `src/session.ts`: `GlobalSessionContainer` | Existing session requirement; get/set/contains/remove; request isolation |
| `RedirectHandler.php` | `src/redirect.ts`: `RedirectHandler` | Default 303 and control transfer |
| `AuthwaveException.php` | `src/errors.ts`: `AuthwaveException` | Base inheritance |
| `SessionNotStartedException.php` | `src/errors.ts`: same name | Absent session rejection |
| `NotLoggedInException.php` | `src/errors.ts`: same name | Missing user, token, data |
| `InsecureProtocolException.php` | `src/errors.ts`: same name | HTTPS policy, localhost and literal `127.0.0.127` exceptions |
| `InvalidUserDataSerializationException.php` | `src/errors.ts`: same name | Low-level decoder shape validation |
| `ResponseCipherDecryptionException.php` | `src/errors.ts`: same name | Declaration preserved; not thrown by normal response processing, as in PHP |
| `ProviderUri/BaseProviderUri.php` | `src/uri.ts`: `BaseProviderUri` | Same constants, RFC1738 query encoding, hex return URI, provider origin |
| `ProviderUri/LoginUri.php` | `src/uri.ts`: `LoginUri` | Login action and encrypted return query |
| `ProviderUri/LogoutUri.php` | `src/uri.ts`: `LogoutUri` | Encrypted destination and precedence |
| `ProviderUri/AdminUri.php` | `src/uri.ts`: `AdminUri` | `/admin/` |
| `ResponseData/BaseResponseData.php` | `src/user.ts`: `BaseResponseData` | Optional message |
| `ResponseData/UserResponseData.php` | `src/user.ts`: `UserResponseData` | ID/email/message accessors |

## Wire compatibility

TweetNaCl's XSalsa20-Poly1305 secretbox matches the reference's `sodium_crypto_secretbox`: raw UTF-8 key bytes, 24-byte nonces, standard base64 ciphertext and IV strings. Request plaintext is the message followed by literal `&secretIv=` and the base64 session IV. Query keys remain `c`, `d`, `i`, `u`. The complete deployment ID is split at the final underscore, not the first.

The differential suite executes PHP's actual source with fixed nonces and compares complete redirect strings, encrypted request bytes, stored user identity, return-query preservation, callback markers and session removal.

## Behaviors intentionally preserved

- An already authenticated login does nothing. Token-only sessions remain logged out.
- The normal response path uses the secret session IV and `id/email`. `Token.decode()` instead uses the request IV and `uuid` (preferred) or `id`.
- Scalar ID/email coercion in the normal response path follows PHP for string/number/boolean values. The lower-level decoder requires string ID/email.
- Raw plus characters in incoming response ciphers are restored after form-query parsing.
- Saved return queries replace callback queries; cleanup removes the response parameter while retaining other raw query bytes and fragments.
- Missing exchange state causes cleanup without authentication. Invalid ciphertext throws a cipher exception; it is not accepted as a user.
- Callback markers are stored before invocation. Throws propagate, cleanup is skipped, replay does not reinvoke. Ordinary session restoration does not call the callback.
- Logout clears only authentication state before redirecting. Other application session values survive. Explicit destination beats configured return URI, which beats provider default. A query-only destination replaces the current request query.
- The default fake email logs out locally. Other fake email addresses use provider logout. Fake login appends its own query, defers the in-memory user refresh, and bypasses the provider.
- `SESSION_STORE_KEY` remains declared but unused. Actual storage uses `Authwave\SessionData` through `SessionData.STORE_KEY`.
- `getUser()` remains deprecated and returns the same compatibility `User` instance as `getAuthUser()`.

## Runtime adaptations

Tokens retain the first complete request plaintext and reject different payloads with the same nonce. Repeating an identical request remains deterministic. The binding is persisted in session serialisation. Legacy tokens without a known binding may decrypt responses but cannot encrypt another request. Login builds the request before replacing pending exchange data.

- Constructor arguments use an options object; URI-like arguments accept strings, `Uri`, and standard `URL` objects. `Uri` provides the operations needed by the client, not the full external PHP HTTP dependency API.
- PHP's native `$_SESSION` has no Node equivalent. `GlobalSessionContainer` wraps an explicitly supplied per-request record. Omitting it throws; no process-global user storage is introduced.
- PHP header-and-exit becomes `RedirectSignal`. Runtime adapters catch it and save before sending 303 responses. Test redirect handlers may return normally.
- JSON session records are rehydrated into classes. Token serialization is server-side only.
- PHP `E_USER_DEPRECATED` becomes Node.js `DeprecationWarning`. The PHP logger's diagnostic token-created message is not an authentication behavior and is left to application logging.
- Node.js/Next.js use opaque 256-bit random session IDs with HTTP-only cookies and a pluggable async server-side store. Express uses the application's `express-session` middleware and saves before output. Store expiration and per-session concurrency control are the production store's responsibility.

## Test boundaries

`test/core.test.mjs` covers the PHP unit-test behaviors and additional JSON/session checks. `test/parity.test.mjs` and `test/php-oracle.php` compare the two implementations directly. `test/runtime.test.mjs` exercises Node/Express over local HTTP and Next.js with actual `NextRequest`/`NextResponse` objects, including callback failures, session isolation, cookies, expiry, and failed persistence.

Browser login/logout against a real configured Authwave provider is not automated here. No claim of live deployment verification is made.
