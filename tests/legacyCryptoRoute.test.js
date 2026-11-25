import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { app } from '../src/app.js';

describe('legacy /api/crypto routes', () => {
  it('returns 404 after route removal', async () => {
    const res = await request(app).post('/api/crypto/encrypt');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ message: 'Tidak ditemukan' });
  });
});
