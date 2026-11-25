import { describe, expect, it } from 'vitest';
import { loadEnv } from '../src/config/env.js';

describe('loadEnv', () => {
  it('provides dev defaults and parses cookie secure', () => {
    const env = loadEnv({ NODE_ENV: 'test', SESSION_SECRET: 'test-secret' });
    expect(env.DB_PORT).toBe(3306);
    expect(env.STORAGE_PATH).toContain('storage');
    expect(env.COOKIE_SECURE).toBe(false);
  });

  it('requires SESSION_SECRET in production', () => {
    expect(() => loadEnv({ NODE_ENV: 'production' })).toThrow(/SESSION_SECRET/);
  });

  it('forces COOKIE_SECURE true in production even when overridden', () => {
    const env = loadEnv({
      NODE_ENV: 'production',
      SESSION_SECRET: 'prod-secret',
      COOKIE_SECURE: 'false',
    });
    expect(env.COOKIE_SECURE).toBe(true);
  });
});
