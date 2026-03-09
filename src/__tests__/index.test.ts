import { createSSOHandler, SSOConfig, SSOCookieConfig } from '../index';

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
  if (typeof (response.headers as any).getSetCookie === 'function') {
    return (response.headers as any).getSetCookie();
  }
  return raw.split(/,(?=\s*[A-Za-z0-9_-]+=)/).map((s) => s.trim());
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
};

const minimalConfig: SSOConfig = {
  cookies: {
    login: [{ name: 'token' }],
    logout: ['token'],
  },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('createSSOHandler', () => {
  describe('login action', () => {
    it('sets all configured cookies with the token value', async () => {
      const { GET } = createSSOHandler(multiCookieConfig);
      const res = await GET(makeRequest({ action: 'login', token: 'abc123' }));

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

      // sessionExpiration cookie
      expect(cookies[1]).toContain('sessionExpiration=abc123');
      expect(cookies[1]).toContain('Path=/');
      expect(cookies[1]).toContain('Max-Age=3600');
      expect(cookies[1]).not.toContain('HttpOnly');
    });

    it('applies default cookie options when not specified', async () => {
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({ action: 'login', token: 'xyz' }));

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
      // Should NOT set any cookies
      expect(getCookies(res).length).toBe(0);
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
      const { GET } = createSSOHandler(config);
      const req = makeRequest({ action: 'login', token: 'abc' });
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

  describe('URL-encoded values', () => {
    it('handles special characters in the token', async () => {
      const { GET } = createSSOHandler(minimalConfig);
      const res = await GET(makeRequest({ action: 'login', token: 'a=b&c=d' }));

      expect(res.status).toBe(200);
      const cookies = getCookies(res);
      expect(cookies.length).toBe(1);
      // The token should be URL-encoded in the cookie value
      expect(cookies[0]).toContain('token=a%3Db%26c%3Dd');
    });
  });
});
