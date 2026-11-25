import request from 'supertest';
import session from 'express-session';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockFindByUsername = vi.fn();
const mockFindById = vi.fn();
const mockVerifyPassword = vi.fn();
const mockLogActivity = vi.fn();

vi.mock('../src/services/users.js', async () => {
  const actual = await vi.importActual('../src/services/users.js');
  return {
    ...actual,
    findByUsername: mockFindByUsername,
    findById: mockFindById,
    verifyPassword: mockVerifyPassword,
  };
});

vi.mock('../src/services/activityLogs.js', () => ({
  logActivity: mockLogActivity,
}));

const { createApp } = await import('../src/app.js');

const validBody = {
  text: '%PDF',
  playfairKeyword: 'MONARCHY',
  aesKeyHex: '2b7e151628aed2a6abf7158809cf4f3c',
  ivHex: '000102030405060708090a0b0c0d0e0f',
};

const activeUser = {
  id: 1,
  username: 'pegawai',
  password_hash: '$2b$12$hashed',
  role: 'pegawai',
  is_active: 1,
  created_at: '2026-01-01T00:00:00.000Z',
  updated_at: '2026-01-01T00:00:00.000Z',
};

function makeApp() {
  return createApp({ sessionStore: new session.MemoryStore() });
}

async function loginAs(app, user = activeUser) {
  mockFindByUsername.mockResolvedValueOnce(user);
  mockVerifyPassword.mockResolvedValueOnce(true);
  mockFindById.mockResolvedValue(user);
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ username: user.username, password: 'password123' });
  expect(res.status).toBe(200);
  return agent;
}

describe('POST /api/simulasi', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
  });

  it('menolak request tanpa autentikasi', async () => {
    const app = makeApp();
    const response = await request(app).post('/api/simulasi').send(validBody);
    expect(response.status).toBe(401);
    expect(response.body).toEqual({ message: 'Autentikasi diperlukan' });
  });

  it('mengembalikan jejak langkah lengkap dan status Cocok', async () => {
    const app = makeApp();
    const agent = await loginAs(app);
    const response = await agent.post('/api/simulasi').send(validBody);
    expect(response.status).toBe(200);
    expect(response.body.steps.matching.status).toBe('Cocok');
    expect(response.body.steps.byteToLetters.letters).toBe('CFFAEEEG');
    expect(response.body.steps.playfairEncrypt.output).toBe('HEIOIUIUFI');
    expect(response.body.ciphertextHex).toMatch(/^[0-9a-f]{32}$/);
  });

  it('menolak teks lebih dari 8 karakter dengan JSON { message }', async () => {
    const app = makeApp();
    const agent = await loginAs(app);
    const response = await agent
      .post('/api/simulasi')
      .send({ ...validBody, text: '123456789' });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ message: 'Teks harus 1-8 karakter ASCII' });
  });

  it('menolak kata kunci Playfair di luar 4-16 huruf', async () => {
    const app = makeApp();
    const agent = await loginAs(app);
    const response = await agent
      .post('/api/simulasi')
      .send({ ...validBody, playfairKeyword: 'ABC' });
    expect(response.status).toBe(400);
    expect(response.body.message).toBe('Kata kunci Playfair harus 4-16 huruf A-Z');
  });

  it('menolak kunci AES/IV yang bukan 32 digit heksadesimal', async () => {
    const app = makeApp();
    const agent = await loginAs(app);
    const response = await agent
      .post('/api/simulasi')
      .send({ ...validBody, aesKeyHex: 'xyz' });
    expect(response.status).toBe(400);
    expect(response.body.message).toBe('Kunci AES-128 harus 32 digit heksadesimal');
  });
});
