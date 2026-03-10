import { createSSOHandler, SSOConfig, SSOCookiePayloadItem } from '../index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(
  params: Record<string, string>,
  headers?: Record<string, string>,
): Request {
  const url = new URL('https://checkout.example.com/api/tapbuy-sso');
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }
  return new Request(url.toString(), { headers });
}

function getCookies(response: Response): string[] {
  // Headers.getSetCookie() may not be available in all runtimes,
  // fall back to parsing the raw headers.
  const raw = response.headers.get('set-cookie');
  if (!raw) return [];
  // Multiple Set-Cookie headers are joined by the runtime with ", " in some
  // implementations, but `Headers.getSetCookie()` is the standard way.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if (typeof (response.headers as any).getSetCookie === 'function') {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (response.headers as any).getSetCookie();
  }
  return raw.split(/,(?=\s*[A-Za-z0-9_-]+=)/).map((s) => s.trim());
}

// ---------------------------------------------------------------------------
// Encryption helper
// ---------------------------------------------------------------------------

const TEST_ENCRYPTION_KEY = 'test-encryption-key-for-sso-123';

/**
 * Encrypt a payload using AES-256-GCM (mirrors PHP encodeCartKey format).
 * Result: base64( iv[12] + tag[16] + cipherText )
 */
async function encryptPayload(
  payload: SSOCookiePayloadItem[],
  key: string,
): Promise<string> {
  const keyBytes = new Uint8Array(32);
  const encoder = new TextEncoder();
  const rawKey = encoder.encode(key);
  keyBytes.set(rawKey.subarray(0, 32));

  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );

  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(payload));

  const encrypted = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    cryptoKey,
    plaintext,
  );

  const encryptedBytes = new Uint8Array(encrypted);
  const cipherText = encryptedBytes.slice(0, encryptedBytes.length - 16);
  const tag = encryptedBytes.slice(encryptedBytes.length - 16);

  // PHP format: iv + tag + cipherText
  const result = new Uint8Array(iv.length + tag.length + cipherText.length);
  result.set(iv, 0);
  result.set(tag, 12);
  result.set(cipherText, 28);

  let binary = '';
  for (let i = 0; i < result.length; i++) {
    binary += String.fromCharCode(result[i]);
  }
  return btoa(binary);
}

/**
 * Encrypt a payload using AES-256-ECB (mirrors PHP phpseclib AES ECB format).
 * Result: base64( AES-256-ECB-PKCS7(json) )
 */
async function encryptPayloadECB(
  payload: SSOCookiePayloadItem[],
  key: string,
): Promise<string> {
  const nodeCrypto = await import('crypto');
  const keyBytes = new Uint8Array(32);
  const encoder = new TextEncoder();
  const rawKey = encoder.encode(key);
  keyBytes.set(rawKey.subarray(0, 32));

  const plaintext = encoder.encode(JSON.stringify(payload));
  const cipher = nodeCrypto.createCipheriv('aes-256-ecb', keyBytes, null);
  const part1: Uint8Array = cipher.update(plaintext);
  const part2: Uint8Array = cipher.final();

  const result = new Uint8Array(part1.length + part2.length);
  result.set(part1);
  result.set(part2, part1.length);

  let binary = '';
  for (let i = 0; i < result.length; i++) {
    binary += String.fromCharCode(result[i]);
  }
  return btoa(binary);
}

// ---------------------------------------------------------------------------
// Config fixtures
// ---------------------------------------------------------------------------

const multiCookieConfig: SSOConfig = {
  cookies: {
    login: [
      { name: 'userId', httpOnly: true, secure: true, sameSite: 'Lax', path: '/fr', domain: '.example.com' },
      { name: 'sessionExpiration', httpOnly: false, secure: true, sameSite: 'Lax', path: '/', domain: '.example.com', maxAge: 3600 },
    ],
    logout: ['userId', 'sessionExpiration'],
  },
  encryptionKey: TEST_ENCRYPTION_KEY,
};

const minimalConfig: SSOConfig = {
  cookies: {
    login: [{ name: 'token' }],
    logout: ['token'],
  },
  encryptionKey: TEST_ENCRYPTION_KEY,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('createSSOHandler', () => {
  describe('login action', () => {
    it('sets all configured cookies from encrypted payload', async () => {
      const payload: SSOCookiePayloadItem[] = [
        { name: 'userId', value: 'abc123', action: 'set' },
        { name: 'sessionExpiration', value: '2026-03-10T12:00:00.000Z', action: 'set' },
      ];
      const token = await encryptPayload(payload, TEST_ENCRYPTION_KEY);
      const { GET } = createSSOHandler(multiCookieConfig);
      const res = await GET(makeRequest({ action: 'login', token }));

      expect(res.status).toBe(200);
      expect(res.headers.get('Content-Type')).toBe('image/gif');

      const cookies = getCookies(res);
      expect(cookies.length).toBe(2);

      // userId cookie
      expect(cookies[0]).toContain('userId=abc123');
      expect(cookies[0]).toContain('Path=/fr');
      expect(cookies[0]).toContain('Domain=.example.com');
      expect(cookies[0]).toContain('HttpOnly');
      expect(cookies[0]).toContain('Secure');
      expect(cookies[0]).toContain('SameSite=Lax');

      // sessionExpiration cookie (not HttpOnly)
      expect(cookies[1]).toContain('sessionExpiration=');
      expect(cookies[1]).toContain('2026-03-10');
      expect(cookies[1]).toContain('Path=/');
      expect(cookies[1]).toContain('Max-Age=3600');
      expect(cookies[1]).not.toContain('HttpOnly');
    });

    it('applies default cookie options when not specified', async () => {
      const payload: SSOCookiePayloadItem[] = [
        { name: 'token', value: 'xyz', action: 'set' },
      ];
      const token = await encryptPayload(payload, TEST_ENCRYPTION_KEY);
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({ action: 'login', token }));

      const cookies = getCookies(res);
      expect(cookies.length).toBe(1);
      expect(cookies[0]).toContain('token=xyz');
      expect(cookies[0]).toContain('HttpOnly');
      expect(cookies[0]).toContain('Secure');
      expect(cookies[0]).toContain('SameSite=Lax');
      expect(cookies[0]).toContain('Path=/');
      expect(cookies[0]).toContain('Max-Age=86400');
    });

    it('returns 400 when token is missing on login', async () => {
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({ action: 'login' }));

      expect(res.status).toBe(400);
      expect(res.headers.get('Content-Type')).toBe('image/gif');
      expect(getCookies(res).length).toBe(0);
    });

    it('handles remove action in payload', async () => {
      const payload: SSOCookiePayloadItem[] = [
        { name: 'userId', value: '', action: 'remove' },
        { name: 'sessionExpiration', value: '', action: 'remove' },
      ];
      const token = await encryptPayload(payload, TEST_ENCRYPTION_KEY);
      const { GET } = createSSOHandler(multiCookieConfig);
      const res = await GET(makeRequest({ action: 'login', token }));

      expect(res.status).toBe(200);
      const cookies = getCookies(res);
      expect(cookies.length).toBe(2);
      for (const cookie of cookies) {
        expect(cookie).toContain('Max-Age=0');
      }
    });

    it('returns 400 when encryption key is wrong', async () => {
      const payload: SSOCookiePayloadItem[] = [
        { name: 'userId', value: 'abc', action: 'set' },
      ];
      const token = await encryptPayload(payload, 'wrong-key-that-does-not-match');
      const { GET } = createSSOHandler(multiCookieConfig);
      const res = await GET(makeRequest({ action: 'login', token }));

      expect(res.status).toBe(400);
      expect(getCookies(res).length).toBe(0);
    });

    it('returns 400 when token is corrupted', async () => {
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({ action: 'login', token: 'not-valid-base64-!!!' }));

      expect(res.status).toBe(400);
      expect(getCookies(res).length).toBe(0);
    });

    it('uses default security options for cookies not in login config', async () => {
      const payload: SSOCookiePayloadItem[] = [
        { name: 'unknownCookie', value: 'some-value', action: 'set' },
      ];
      const token = await encryptPayload(payload, TEST_ENCRYPTION_KEY);
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({ action: 'login', token }));

      expect(res.status).toBe(200);
      const cookies = getCookies(res);
      expect(cookies.length).toBe(1);
      expect(cookies[0]).toContain('unknownCookie=some-value');
      expect(cookies[0]).toContain('HttpOnly');
      expect(cookies[0]).toContain('Secure');
      expect(cookies[0]).toContain('SameSite=Lax');
      expect(cookies[0]).toContain('Path=/');
    });
  });

  describe('logout action', () => {
    it('expires all configured cookies', async () => {
      const { GET } = createSSOHandler(multiCookieConfig);
      const res = await GET(makeRequest({ action: 'logout' }));

      expect(res.status).toBe(200);

      const cookies = getCookies(res);
      expect(cookies.length).toBe(2);

      // Both cookies should be expired
      for (const cookie of cookies) {
        expect(cookie).toContain('Max-Age=0');
      }

      // userId should inherit path/domain from login config
      expect(cookies[0]).toContain('userId=');
      expect(cookies[0]).toContain('Path=/fr');
      expect(cookies[0]).toContain('Domain=.example.com');

      // sessionExpiration should inherit path/domain from login config
      expect(cookies[1]).toContain('sessionExpiration=');
      expect(cookies[1]).toContain('Path=/');
    });

    it('does not require a token for logout', async () => {
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({ action: 'logout' }));

      expect(res.status).toBe(200);
      const cookies = getCookies(res);
      expect(cookies.length).toBe(1);
      expect(cookies[0]).toContain('Max-Age=0');
    });
  });

  describe('invalid requests', () => {
    it('returns 400 when action is missing', async () => {
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({}));

      expect(res.status).toBe(400);
    });

    it('returns 400 when action is invalid', async () => {
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({ action: 'unknown' }));

      expect(res.status).toBe(400);
    });
  });

  describe('response format', () => {
    it('returns a 1x1 transparent GIF', async () => {
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({ action: 'logout' }));

      const buffer = await res.arrayBuffer();
      const bytes = new Uint8Array(buffer);

      // GIF89a magic bytes
      expect(bytes[0]).toBe(0x47); // G
      expect(bytes[1]).toBe(0x49); // I
      expect(bytes[2]).toBe(0x46); // F
      expect(bytes[3]).toBe(0x38); // 8
      expect(bytes[4]).toBe(0x39); // 9
      expect(bytes[5]).toBe(0x61); // a
    });

    it('sets no-cache headers', async () => {
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({ action: 'logout' }));

      expect(res.headers.get('Cache-Control')).toContain('no-store');
      expect(res.headers.get('Pragma')).toBe('no-cache');
    });
  });

  describe('CORS', () => {
    it('does not set CORS headers when no allowedOrigins configured', async () => {
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(
        makeRequest({ action: 'logout' }, { Origin: 'https://evil.com' }),
      );

      expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();
    });

    it('sets CORS headers when origin matches', async () => {
      const config: SSOConfig = {
        ...minimalConfig,
        allowedOrigins: ['https://checkout.example.com'],
      };
      const { GET } = createSSOHandler(config);
      const res = await GET(
        makeRequest(
          { action: 'logout' },
          { Origin: 'https://checkout.example.com' },
        ),
      );

      expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
        'https://checkout.example.com',
      );
      expect(res.headers.get('Access-Control-Allow-Credentials')).toBe('true');
    });

    it('supports RegExp patterns for origins', async () => {
      const config: SSOConfig = {
        ...minimalConfig,
        allowedOrigins: [/\.example\.com$/],
      };
      const { GET } = createSSOHandler(config);
      const res = await GET(
        makeRequest(
          { action: 'logout' },
          { Origin: 'https://checkout.example.com' },
        ),
      );

      expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
        'https://checkout.example.com',
      );
    });

    it('does not set CORS headers when origin does not match', async () => {
      const config: SSOConfig = {
        ...minimalConfig,
        allowedOrigins: ['https://checkout.example.com'],
      };
      const { GET } = createSSOHandler(config);
      const res = await GET(
        makeRequest({ action: 'logout' }, { Origin: 'https://evil.com' }),
      );

      expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();
    });
  });

  describe('onComplete callback', () => {
    it('calls onComplete with action and request on login', async () => {
      const onComplete = jest.fn();
      const config: SSOConfig = { ...minimalConfig, onComplete };
      const payload: SSOCookiePayloadItem[] = [
        { name: 'token', value: 'abc', action: 'set' },
      ];
      const token = await encryptPayload(payload, TEST_ENCRYPTION_KEY);
      const { GET } = createSSOHandler(config);
      const req = makeRequest({ action: 'login', token });
      await GET(req);

      expect(onComplete).toHaveBeenCalledTimes(1);
      expect(onComplete).toHaveBeenCalledWith('login', req);
    });

    it('calls onComplete with action and request on logout', async () => {
      const onComplete = jest.fn();
      const config: SSOConfig = { ...minimalConfig, onComplete };
      const { GET } = createSSOHandler(config);
      const req = makeRequest({ action: 'logout' });
      await GET(req);

      expect(onComplete).toHaveBeenCalledTimes(1);
      expect(onComplete).toHaveBeenCalledWith('logout', req);
    });

    it('does not call onComplete on error', async () => {
      const onComplete = jest.fn();
      const config: SSOConfig = { ...minimalConfig, onComplete };
      const { GET } = createSSOHandler(config);
      await GET(makeRequest({}));

      expect(onComplete).not.toHaveBeenCalled();
    });
  });

  describe('AES-256-ECB mode', () => {
    const ecbConfig: SSOConfig = {
      cookies: {
        login: [
          { name: 'userId', httpOnly: true, secure: true, path: '/', domain: '.example.com' },
          { name: 'session', httpOnly: false, secure: true, path: '/' },
        ],
        logout: ['userId', 'session'],
      },
      encryptionKey: TEST_ENCRYPTION_KEY,
      encryptionAlgorithm: 'aes-256-ecb',
    };

    it('decrypts ECB payload and sets cookies', async () => {
      const payload: SSOCookiePayloadItem[] = [
        { name: 'userId', value: 'user-42', action: 'set' },
        { name: 'session', value: '2026-12-31T00:00:00.000Z', action: 'set' },
      ];
      const token = await encryptPayloadECB(payload, TEST_ENCRYPTION_KEY);
      const { GET } = createSSOHandler(ecbConfig);
      const res = await GET(makeRequest({ action: 'login', token }));

      expect(res.status).toBe(200);
      const cookies = getCookies(res);
      expect(cookies.length).toBe(2);
      expect(cookies[0]).toContain('userId=user-42');
      expect(cookies[0]).toContain('HttpOnly');
      expect(cookies[0]).toContain('Domain=.example.com');
      expect(cookies[1]).toContain('session=');
      expect(cookies[1]).toContain('2026-12-31');
      expect(cookies[1]).not.toContain('HttpOnly');
    });

    it('handles remove action in ECB payload', async () => {
      const payload: SSOCookiePayloadItem[] = [
        { name: 'userId', value: '', action: 'remove' },
      ];
      const token = await encryptPayloadECB(payload, TEST_ENCRYPTION_KEY);
      const { GET } = createSSOHandler(ecbConfig);
      const res = await GET(makeRequest({ action: 'login', token }));

      expect(res.status).toBe(200);
      const cookies = getCookies(res);
      expect(cookies.length).toBe(1);
      expect(cookies[0]).toContain('Max-Age=0');
    });

    it('returns 400 when ECB key is wrong', async () => {
      const payload: SSOCookiePayloadItem[] = [
        { name: 'userId', value: 'abc', action: 'set' },
      ];
      const token = await encryptPayloadECB(payload, 'wrong-key-not-matching');
      const { GET } = createSSOHandler(ecbConfig);
      const res = await GET(makeRequest({ action: 'login', token }));

      expect(res.status).toBe(400);
      expect(getCookies(res).length).toBe(0);
    });

    it('returns 400 when ECB token is corrupted', async () => {
      const { GET } = createSSOHandler(ecbConfig);
      const res = await GET(makeRequest({ action: 'login', token: 'corrupted!!!' }));

      expect(res.status).toBe(400);
      expect(getCookies(res).length).toBe(0);
    });

    it('logout works in ECB mode', async () => {
      const { GET } = createSSOHandler(ecbConfig);
      const res = await GET(makeRequest({ action: 'logout' }));

      expect(res.status).toBe(200);
      const cookies = getCookies(res);
      expect(cookies.length).toBe(2);
      for (const cookie of cookies) {
        expect(cookie).toContain('Max-Age=0');
      }
    });
  });

});
