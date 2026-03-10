/**
 * @tapbuy-public/sso
 *
 * Framework-agnostic SSO handler for Tapbuy checkout.
 * Decrypts an encrypted cookie payload and sets/deletes cookies accordingly.
 *
 * Works with any framework that uses the Web standard Request/Response API:
 * Next.js (App Router), Nuxt, Remix, Deno, Bun, Cloudflare Workers, etc.
 *
 * Supported encryption algorithms:
 * - **AES-256-GCM** (default): uses Web Crypto API — works everywhere.
 * - **AES-256-ECB**: uses Node.js `crypto` module — requires Node.js runtime.
 *
 * The `token` query parameter contains an encrypted JSON payload
 * describing which cookies to set/remove and their values.
 * The encryption key must match the retailer's `encryption_key` on the API side.
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
 *   encryptionKey: process.env.TAPBUY_SSO_ENCRYPTION_KEY!,
 *   // encryptionAlgorithm: 'aes-256-ecb', // optional, default is 'aes-256-gcm'
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

/**
 * A single cookie operation from the encrypted payload.
 * The API builds an array of these, encrypts it, and passes it as the `token` query param.
 */
export interface SSOCookiePayloadItem {
  /** Cookie name. Must match a name in `cookies.login` for security options. */
  name: string;
  /** Cookie value to set. */
  value: string;
  /** Whether to set or remove (expire) this cookie. */
  action: 'set' | 'remove';
}

/** Supported encryption algorithms for the SSO token. */
export type SSOEncryptionAlgorithm = 'aes-256-gcm' | 'aes-256-ecb';

/** Main configuration object for the SSO handler. */
export interface SSOConfig {
  cookies: {
    /**
     * Cookie security options for login.
     * Defines httpOnly, secure, sameSite, path, domain, maxAge for each cookie.
     * Cookie names and values come from the encrypted payload.
     */
    login: SSOCookieConfig[];
    /**
     * Cookie names to delete when `action=logout`.
     * They are expired by setting `Max-Age=0`.
     */
    logout: string[];
  };
  /**
   * AES-256-GCM encryption key.
   * Must match the `encryption_key` retailer config on the API side.
   * The `token` query param is decrypted using this key to get the cookie payload.
   */
  encryptionKey: string;
  /**
   * Encryption algorithm used for the `token` query parameter.
   * - `'aes-256-gcm'` (default): Web Crypto API — works everywhere.
   * - `'aes-256-ecb'`: Node.js `crypto` module — requires Node.js runtime.
   * @default 'aes-256-gcm'
   */
  encryptionAlgorithm?: SSOEncryptionAlgorithm;
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
// Encrypted mode helpers
// ---------------------------------------------------------------------------

/**
 * Decrypt an AES-256-GCM encrypted payload.
 *
 * The encrypted data format (matching PHP `encodeCartKey`):
 *   base64( iv[12 bytes] + tag[16 bytes] + cipherText )
 *
 * Web Crypto API expects: cipherText + tag (tag appended at the end).
 *
 * @param encryptedBase64 - Base64-encoded encrypted string from the `token` query param.
 * @param encryptionKey   - Shared secret key (will be padded/truncated to 32 bytes).
 * @returns Parsed array of cookie payload items.
 */
async function decryptPayload(
  encryptedBase64: string,
  encryptionKey: string,
): Promise<SSOCookiePayloadItem[]> {
  // Pad/truncate key to 32 bytes — matches PHP: substr(str_pad($key, 32, "\0"), 0, 32)
  const keyBytes = new Uint8Array(32);
  const encoder = new TextEncoder();
  const rawKey = encoder.encode(encryptionKey);
  keyBytes.set(rawKey.subarray(0, 32));

  // Decode base64
  const binaryStr = atob(encryptedBase64);
  const data = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) {
    data[i] = binaryStr.charCodeAt(i);
  }

  // PHP format: iv(12) + tag(16) + cipherText
  const iv = data.slice(0, 12);
  const tag = data.slice(12, 28);
  const cipherText = data.slice(28);

  // Web Crypto expects: cipherText + tag (tag appended)
  const combined = new Uint8Array(cipherText.length + tag.length);
  combined.set(cipherText);
  combined.set(tag, cipherText.length);

  // Import key
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );

  // Decrypt
  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    cryptoKey,
    combined,
  );

  const jsonStr = new TextDecoder().decode(decrypted);
  return JSON.parse(jsonStr);
}

/**
 * Decrypt an AES-256-ECB encrypted payload.
 *
 * ECB mode is not supported by the Web Crypto API, so this uses the Node.js
 * `crypto` module. Works in Next.js, Nuxt, Remix, Deno, and Bun.
 *
 * The encrypted data format (matching PHP `phpseclib` AES ECB with PKCS7 padding):
 *   base64( AES-256-ECB-PKCS7(json) )
 *
 * @param encryptedBase64 - Base64-encoded encrypted string from the `token` query param.
 * @param encryptionKey   - Shared secret key (will be padded/truncated to 32 bytes).
 * @returns Parsed array of cookie payload items.
 */
async function decryptPayloadECB(
  encryptedBase64: string,
  encryptionKey: string,
): Promise<SSOCookiePayloadItem[]> {
  // Pad/truncate key to 32 bytes — matches PHP: substr(str_pad($key, 32, "\0"), 0, 32)
  const keyBytes = new Uint8Array(32);
  const encoder = new TextEncoder();
  const rawKey = encoder.encode(encryptionKey);
  keyBytes.set(rawKey.subarray(0, 32));

  // Decode base64
  const binaryStr = atob(encryptedBase64);
  const data = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) {
    data[i] = binaryStr.charCodeAt(i);
  }

  // ECB mode is not supported by Web Crypto API.
  // Use Node.js crypto module (available in Next.js, Nuxt, Remix, Deno, Bun).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let nodeCrypto: any;
  try {
    nodeCrypto = await import('crypto');
  } catch {
    throw new Error(
      'AES-256-ECB requires the Node.js crypto module. ' +
        'Use AES-256-GCM for environments without Node.js (e.g. Cloudflare Workers).',
    );
  }

  const decipher = nodeCrypto.createDecipheriv('aes-256-ecb', keyBytes, null);
  const part1: Uint8Array = decipher.update(data);
  const part2: Uint8Array = decipher.final();

  const result = new Uint8Array(part1.length + part2.length);
  result.set(part1);
  result.set(part2, part1.length);

  const jsonStr = new TextDecoder().decode(result);
  return JSON.parse(jsonStr);
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
 * - `token`  — encrypted cookie payload, base64-encoded (required for login)
 * - `action` — `"login"` or `"logout"` (required)
 */
export function createSSOHandler(config: SSOConfig): {
  GET: (request: Request) => Response | Promise<Response>;
} {
  const { cookies, encryptionKey, encryptionAlgorithm = 'aes-256-gcm', allowedOrigins = [], onComplete } = config;

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

      // Decrypt the encrypted cookie payload
      try {
        const decrypt = encryptionAlgorithm === 'aes-256-ecb' ? decryptPayloadECB : decryptPayload;
        const payload = await decrypt(token, encryptionKey);

        for (const item of payload) {
          // Find matching cookie config for security options (httpOnly, secure, etc.)
          const cookieCfg = cookies.login.find((c) => c.name === item.name);

          if (item.action === 'set') {
            const serialized = serializeCookie(item.name, item.value, {
              httpOnly: cookieCfg?.httpOnly ?? true,
              secure: cookieCfg?.secure ?? true,
              sameSite: cookieCfg?.sameSite ?? 'Lax',
              path: cookieCfg?.path ?? '/',
              domain: cookieCfg?.domain,
              maxAge: cookieCfg?.maxAge ?? 86400,
            });
            headers.append('Set-Cookie', serialized);
          } else if (item.action === 'remove') {
            const serialized = serializeCookie(item.name, '', {
              httpOnly: cookieCfg?.httpOnly ?? true,
              secure: cookieCfg?.secure ?? true,
              sameSite: cookieCfg?.sameSite ?? 'Lax',
              path: cookieCfg?.path ?? '/',
              domain: cookieCfg?.domain,
              maxAge: 0,
            });
            headers.append('Set-Cookie', serialized);
          }
        }
      } catch {
        // Decryption or JSON parse failed — bad token
        return new Response(TRANSPARENT_GIF, { status: 400, headers });
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
