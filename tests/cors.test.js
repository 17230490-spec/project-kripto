import request from 'supertest';
import session from 'express-session';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';

function makeApp() {
  return createApp({ sessionStore: new session.MemoryStore() });
}

describe('CORS', () => {
  it('answers preflight for the configured frontend origin with credentials', async () => {
    const response = await request(makeApp())
      .options('/api/auth/login')
      .set('Origin', 'https://fe-kripto.vercel.app')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type');

    expect(response.status).toBe(204);
    expect(response.headers['access-control-allow-origin']).toBe('https://fe-kripto.vercel.app');
    expect(response.headers['access-control-allow-credentials']).toBe('true');
    expect(response.headers['access-control-allow-methods']).toContain('POST');
  });

  it('does not allow unknown origins', async () => {
    const response = await request(makeApp())
      .options('/api/auth/login')
      .set('Origin', 'https://evil.example')
      .set('Access-Control-Request-Method', 'POST');

    expect(response.headers['access-control-allow-origin']).toBeUndefined();
  });
});
