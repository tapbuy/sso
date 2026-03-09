/**
 * @tapbuy-public/sso
 *
 * Framework-agnostic SSO handler for Tapbuy checkout.
 * Sets/deletes auth cookies from a token passed via query parameter.
 *
 * Works with any framework that uses the Web standard Request/Response API:
 * Next.js (App Router), Nuxt, Remix, Deno, Bun, Cloudflare Workers, etc.
 *
 * @example
 * // Next.js — app/api/tapbuy-sso/route.ts
 * import { createSSOHandler } from '@tapbuy-public/sso'
 *
 * export const { GET } = createSSOHandler({
 *   cookies: {
 *     login: [
 *       { name: 'userId', httpOnly: true, path: '/', domain: '.example.com' },
 *     ],
 *     logout: ['userId'],
 *   },
 * })
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Configuration for a single cookie to set on login. */
export interface SSOCookieConfig {
  /** Cookie name (e.g. "userId", "userToken"). */
  name: string;
  /** Whether the cookie is inaccessible to JavaScript. @default true */
  httpOnly?: boolean;
  /** Only send cookie over HTTPS. @default true */
  secure?: boolean;
  /** SameSite attribute. @default "Lax" */
  sameSite?: 'Strict' | 'Lax' | 'None';
  /** Cookie path. @default "/" */
  path?: string;
  /** Cookie domain (e.g. ".website.com"). If omitted, defaults to the request host. */
  domain?: string;
  /** Cookie max-age in seconds. @default 86400 (24 h) */
  maxAge?: number;
}

/** Main configuration object for the SSO handler. */
export interface SSOConfig {
  cookies: {
    /**
     * Cookies to set when `action=login`.
     * Each cookie receives the token value from the `token` query parameter.
     */
    login: SSOCookieConfig[];
    /**
     * Cookie names to delete when `action=logout`.
     * They are expired by setting `Max-Age=0`.
     */
    logout: string[];
  };
  /**
   * Optional list of allowed origins for CORS.
   * When provided, the handler adds `Access-Control-Allow-Origin` for matching origins.
   * Supports exact strings or RegExp patterns.
   * @default [] (no CORS headers)
   */
  allowedOrigins?: (string | RegExp)[];
  /**
   * Optional callback fired after cookies are set/deleted, before the response is returned.
   * Useful for side-effects like logging or analytics.
   */
  onComplete?: (action: 'login' | 'logout', request: Request) => void | Promise<void>;
}

// ---------------------------------------------------------------------------
// 1x1 transparent GIF
// ---------------------------------------------------------------------------

/** Minimal 1×1 transparent GIF (43 bytes). */
const TRANSPARENT_GIF = new Uint8Array([
  0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
  0x01, 0x00, 0x01, 0x00,             // 1×1
  0x80, 0x00, 0x00,                   // GCT flag, 2 colors
  0x00, 0x00, 0x00,                   // color 0: black
  0xff, 0xff, 0xff,                   // color 1: white
  0x21, 0xf9, 0x04,                   // GCE
  0x01, 0x00, 0x00, 0x00, 0x00,       // transparent index 0
  0x2c,                               // image descriptor
  0x00, 0x00, 0x00, 0x00,             // left, top
  0x01, 0x00, 0x01, 0x00,             // width, height
  0x00,                               // packed byte
  0x02, 0x02, 0x44, 0x01, 0x00,       // LZW min code size + data
  0x3b,                               // trailer
]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function serializeCookie(
  name: string,
  value: string,
  options: {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: string;
    path?: string;
    domain?: string;
    maxAge?: number;
  },
): string {
  const parts: string[] = [`${encodeURIComponent(name)}=${encodeURIComponent(value)}`];

  if (options.path) parts.push(`Path=${options.path}`);
  if (options.domain) parts.push(`Domain=${options.domain}`);
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  if (options.secure) parts.push('Secure');
  if (options.httpOnly) parts.push('HttpOnly');
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);

  return parts.join('; ');
}

function matchesOrigin(origin: string, allowed: (string | RegExp)[]): boolean {
  return allowed.some((pattern) => {
    if (typeof pattern === 'string') return origin === pattern;
    return pattern.test(origin);
  });
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

/**
 * Create a SSO route handler.
 *
 * Returns an object with a `GET` method compatible with the Web standard
 * `Request → Response` signature (Next.js App Router, etc.).
 *
 * Query parameters:
 * - `token`  — the auth token value (required for login)
 * - `action` — `"login"` or `"logout"` (required)
 */
export function createSSOHandler(config: SSOConfig): {
  GET: (request: Request) => Response | Promise<Response>;
} {
  const { cookies, allowedOrigins = [], onComplete } = config;

  async function GET(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const token = url.searchParams.get('token');
    const action = url.searchParams.get('action') as 'login' | 'logout' | null;

    // Build common response headers
    const headers = new Headers({
      'Content-Type': 'image/gif',
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
      'Pragma': 'no-cache',
    });

    // CORS — only if an origin matches the allow-list
    const origin = request.headers.get('Origin');
    if (origin && allowedOrigins.length > 0 && matchesOrigin(origin, allowedOrigins)) {
      headers.set('Access-Control-Allow-Origin', origin);
      headers.set('Access-Control-Allow-Credentials', 'true');
    }

    // Validate action
    if (action !== 'login' && action !== 'logout') {
      return new Response(TRANSPARENT_GIF, { status: 400, headers });
    }

    // Login — set cookies
    if (action === 'login') {
      if (!token) {
        return new Response(TRANSPARENT_GIF, { status: 400, headers });
      }

      for (const cookieCfg of cookies.login) {
        const serialized = serializeCookie(cookieCfg.name, token, {
          httpOnly: cookieCfg.httpOnly ?? true,
          secure: cookieCfg.secure ?? true,
          sameSite: cookieCfg.sameSite ?? 'Lax',
          path: cookieCfg.path ?? '/',
          domain: cookieCfg.domain,
          maxAge: cookieCfg.maxAge ?? 86400,
        });
        headers.append('Set-Cookie', serialized);
      }
    }

    // Logout — expire cookies
    if (action === 'logout') {
      for (const cookieName of cookies.logout) {
        // Find matching login config for path/domain, or use defaults
        const loginCfg = cookies.login.find((c) => c.name === cookieName);
        const serialized = serializeCookie(cookieName, '', {
          httpOnly: loginCfg?.httpOnly ?? true,
          secure: loginCfg?.secure ?? true,
          sameSite: loginCfg?.sameSite ?? 'Lax',
          path: loginCfg?.path ?? '/',
          domain: loginCfg?.domain,
          maxAge: 0, // Expire immediately
        });
        headers.append('Set-Cookie', serialized);
      }
    }

    // Optional side-effect callback
    if (onComplete) {
      await onComplete(action, request);
    }

    return new Response(TRANSPARENT_GIF, { status: 200, headers });
  }

  return { GET };
}

// Default export for convenience
export default createSSOHandler;
