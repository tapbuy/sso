# @tapbuy-public/sso

Framework-agnostic SSO handler for Tapbuy checkout. Sets and expires auth cookies from a JWT token passed via URL query parameter.

Works with any runtime that supports the Web standard `Request`/`Response` API: **Next.js (App Router)**, Nuxt, Remix, Deno, Bun, Cloudflare Workers, etc.

## How it works

1. The Tapbuy API returns a `singleSignOnURL` pointing to the retailer's SSO endpoint.
2. The Tapbuy checkout renders a hidden `<img src="{singleSignOnURL}">` pixel.
3. The retailer's SSO endpoint (powered by this package) reads the `token` and `action` query params, sets or expires cookies, and returns a 1×1 transparent GIF.

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
});
```

## API

### `createSSOHandler(config: SSOConfig)`

Returns `{ GET: (request: Request) => Response | Promise<Response> }`.

The `GET` handler reads two query parameters from the request URL:

| Parameter | Required          | Description                         |
| --------- | ----------------- | ----------------------------------- |
| `action`  | Always            | `"login"` or `"logout"`             |
| `token`   | When action=login | The JWT / auth token value to store |

**On login**: sets each cookie from `config.cookies.login` with the token as value.

**On logout**: expires each cookie name listed in `config.cookies.logout` by setting `Max-Age=0`. Path and domain are inherited from the matching login config (if any).

**Response**: Always returns a 1×1 transparent GIF (`image/gif`) with no-cache headers.

**Error**: Returns HTTP 400 (still a GIF) when `action` is missing/invalid or when `token` is missing on login.

### `SSOConfig`

```typescript
interface SSOConfig {
  cookies: {
    login: SSOCookieConfig[];
    logout: string[];
  };
  /** Optional allowed origins for CORS headers. */
  allowedOrigins?: (string | RegExp)[];
  /** Optional callback after cookies are set/deleted. */
  onComplete?: (action: 'login' | 'logout', request: Request) => void | Promise<void>;
}
```

### `SSOCookieConfig`

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

## How to configure the Tapbuy API

The Tapbuy API adapter must return a `singleSignOnURL` in the login/guest response. The URL should point to the retailer's SSO endpoint with `{jwt}` and `{action}` placeholders:

```
https://example.com/api/tapbuy-sso?token={jwt}&action={action}
```

The Tapbuy checkout replaces `{jwt}` with the customer's JWT token and `{action}` with `login` or `logout` before firing the pixel.

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

## Publishing

```bash
npm login
yarn publish --access public
```

## License

MIT
