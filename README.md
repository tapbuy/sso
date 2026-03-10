# @tapbuy-public/sso

Framework-agnostic SSO handler for Tapbuy checkout. Decrypts an encrypted cookie payload passed via URL query parameter and sets or removes cookies accordingly.

Works with any runtime that supports the Web standard `Request`/`Response` API: **Next.js (App Router)**, Nuxt, Remix, Deno, Bun, Cloudflare Workers, etc.

## How it works

1. The Tapbuy API returns a `singleSignOnURL` pointing to the retailer's SSO endpoint.
2. The Tapbuy checkout renders a hidden `<img src="{singleSignOnURL}">` pixel.
3. The retailer's SSO endpoint (powered by this package) reads the `token` and `action` query params, decrypts the encrypted payload, sets or removes cookies based on its content, and returns a 1×1 transparent GIF.

The `token` query parameter contains a **base64-encoded encrypted JSON payload** — an array of cookie operations (`set` / `remove`) with names and values. The encryption key must match the retailer's `encryption_key` configured on the Tapbuy API side.

Because the Tapbuy checkout runs on the retailer's subdomain (e.g. `checkout.retailer.com`), the pixel request is **same-site** — no third-party cookie issues.

## Installation

```bash
yarn add @tapbuy-public/sso
```

## Usage

### Next.js (App Router)

Create a route handler at `app/api/tapbuy-sso/route.ts`:

```typescript
import { createSSOHandler } from '@tapbuy-public/sso';

export const { GET } = createSSOHandler({
  cookies: {
    login: [
      {
        name: 'userId',
        httpOnly: true,
        path: '/',
        domain: '.example.com',
      },
      {
        name: 'sessionExpiration',
        httpOnly: false,
        path: '/',
        domain: '.example.com',
        maxAge: 3600,
      },
    ],
    logout: ['userId', 'sessionExpiration'],
  },
  encryptionKey: process.env.TAPBUY_SSO_ENCRYPTION_KEY!,
});
```

That's it — one file. No other changes required.

### Minimal example

```typescript
import { createSSOHandler } from '@tapbuy-public/sso';

export const { GET } = createSSOHandler({
  cookies: {
    login: [
      {
        name: 'userToken',
        httpOnly: false,
        path: '/',
      },
    ],
    logout: ['userToken'],
  },
  encryptionKey: process.env.TAPBUY_SSO_ENCRYPTION_KEY!,
});
```

### Using AES-256-ECB (Node.js only)

```typescript
export const { GET } = createSSOHandler({
  cookies: {
    login: [{ name: 'userToken', httpOnly: true, path: '/' }],
    logout: ['userToken'],
  },
  encryptionKey: process.env.TAPBUY_SSO_ENCRYPTION_KEY!,
  encryptionAlgorithm: 'aes-256-ecb',
});
```

## API

### `createSSOHandler(config: SSOConfig)`

Returns `{ GET: (request: Request) => Response | Promise<Response> }`.

The `GET` handler reads two query parameters from the request URL:

| Parameter | Required          | Description                                                                 |
| --------- | ----------------- | --------------------------------------------------------------------------- |
| `action`  | Always            | `"login"` or `"logout"`                                                     |
| `token`   | When action=login | Base64-encoded encrypted JSON payload describing which cookies to set/remove |

**Encrypted payload format**: The decrypted `token` is a JSON array of cookie operations:

```typescript
interface SSOCookiePayloadItem {
  name: string;           // Cookie name
  value: string;          // Cookie value to set
  action: 'set' | 'remove'; // Whether to set or remove (expire) this cookie
}
```

**On login**: decrypts the `token`, then for each item in the payload:
- `action: 'set'` — sets the cookie with the given value, using security options from the matching `cookies.login` config.
- `action: 'remove'` — expires the cookie by setting `Max-Age=0`.

**On logout**: expires each cookie name listed in `config.cookies.logout` by setting `Max-Age=0`. Path and domain are inherited from the matching login config (if any).

**Response**: Always returns a 1×1 transparent GIF (`image/gif`) with no-cache headers.

**Error**: Returns HTTP 400 (still a GIF) when `action` is missing/invalid, when `token` is missing on login, or when decryption fails.

### `SSOConfig`

```typescript
interface SSOConfig {
  cookies: {
    /** Cookie security options for login (httpOnly, secure, path, domain, etc.). Cookie names and values come from the encrypted payload. */
    login: SSOCookieConfig[];
    /** Cookie names to delete on logout. */
    logout: string[];
  };
  /** AES-256 encryption key. Must match the retailer's encryption_key on the API side. */
  encryptionKey: string;
  /** Encryption algorithm. @default 'aes-256-gcm' */
  encryptionAlgorithm?: 'aes-256-gcm' | 'aes-256-ecb';
  /** Optional allowed origins for CORS headers. */
  allowedOrigins?: (string | RegExp)[];
  /** Optional callback after cookies are set/deleted. */
  onComplete?: (action: 'login' | 'logout', request: Request) => void | Promise<void>;
}
```

### `SSOCookieConfig`

Defines **security options** for a cookie. The cookie name and value are provided by the encrypted payload at runtime.

```typescript
interface SSOCookieConfig {
  name: string;
  httpOnly?: boolean;   // default: true
  secure?: boolean;     // default: true
  sameSite?: 'Strict' | 'Lax' | 'None';  // default: "Lax"
  path?: string;        // default: "/"
  domain?: string;      // default: request host
  maxAge?: number;      // default: 86400 (24h)
}
```

### Encryption algorithms

| Algorithm       | Default | Runtime requirement                | Notes                                    |
| --------------- | ------- | ---------------------------------- | ---------------------------------------- |
| `aes-256-gcm`   | Yes     | Web Crypto API (works everywhere)  | Recommended. Authenticated encryption.   |
| `aes-256-ecb`   | No      | Node.js `crypto` module            | Legacy. Use only if required by the API. |

## How to configure the Tapbuy API

The Tapbuy API adapter must return a `singleSignOnURL` in the login/guest response. The URL should point to the retailer's SSO endpoint with `{token}` and `{action}` placeholders:

```
https://example.com/api/tapbuy-sso?token={token}&action={action}
```

The Tapbuy checkout replaces `{token}` with the encrypted cookie payload and `{action}` with `login` or `logout` before firing the pixel.

The `encryption_key` configured on the Tapbuy API side must match the `encryptionKey` passed to `createSSOHandler`.

## Development

```bash
# Install dependencies
yarn

# Run tests
yarn test

# Build
yarn build

# Lint
yarn lint
```
