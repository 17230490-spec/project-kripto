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

function makeApp() {
  const sessionStore = new session.MemoryStore();
  return { app: createApp({ sessionStore }), sessionStore };
}

const activeUser = {
  id: 1,
  username: 'admin',
  password_hash: '$2b$10$hashed',
  role: 'admin',
  is_active: 1,
  created_at: '2026-01-01T00:00:00.000Z',
  updated_at: '2026-01-01T00:00:00.000Z',
};

describe('auth API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
  });

  it('login success sets cookie and returns user sans password_hash', async () => {
    mockFindByUsername.mockResolvedValue(activeUser);
    mockVerifyPassword.mockResolvedValue(true);
    const { app } = makeApp();

    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'admin123' });

    expect(res.status).toBe(200);
    expect(res.headers['set-cookie']).toEqual(expect.arrayContaining([expect.stringMatching(/connect\.sid=/)]));
    expect(res.body).toEqual({
      user: {
        id: 1,
        username: 'admin',
        role: 'admin',
        is_active: 1,
        created_at: '2026-01-01T00:00:00.000Z',
        updated_at: '2026-01-01T00:00:00.000Z',
      },
    });
    expect(res.body.user).not.toHaveProperty('password_hash');
    expect(mockLogActivity).toHaveBeenCalledWith(expect.objectContaining({ userId: 1, activity: 'LOGIN', result: 'SUCCESS' }));
  });

  it('regenerates session on login to prevent fixation', async () => {
    mockFindByUsername.mockResolvedValue(activeUser);
    mockVerifyPassword.mockResolvedValue(true);
    mockFindById.mockResolvedValue(activeUser);
    const { app, sessionStore } = makeApp();

    const first = await request(app).post('/api/auth/login').send({ username: 'admin', password: 'admin123' });
    expect(first.status).toBe(200);
    const firstCookie = first.headers['set-cookie'].find((c) => c.startsWith('connect.sid='));
    expect(firstCookie).toBeTruthy();
    const beforeIds = Object.keys(sessionStore.sessions);

    const second = await request(app)
      .post('/api/auth/login')
      .set('Cookie', firstCookie)
      .send({ username: 'admin', password: 'admin123' });
    expect(second.status).toBe(200);
    const secondCookie = second.headers['set-cookie'].find((c) => c.startsWith('connect.sid='));
    expect(secondCookie).toBeTruthy();
    expect(secondCookie.split(';')[0]).not.toBe(firstCookie.split(';')[0]);

    const oldSessionMe = await request(app).get('/api/auth/me').set('Cookie', firstCookie);
    expect(oldSessionMe.status).toBe(401);
    const newSessionMe = await request(app).get('/api/auth/me').set('Cookie', secondCookie);
    expect(newSessionMe.status).toBe(200);
    expect(Object.keys(sessionStore.sessions)).not.toEqual(beforeIds);
  });

  it('wrong password returns generic 401 and logs failed login', async () => {
    mockFindByUsername.mockResolvedValue(activeUser);
    mockVerifyPassword.mockResolvedValue(false);
    const { app } = makeApp();

    const res = await request(app).post('/api/auth/login').send({ username: 'admin', password: 'wrong' });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ message: 'Nama pengguna atau kata sandi salah' });
    expect(mockLogActivity).toHaveBeenCalledWith({ userId: 1, activity: 'LOGIN', result: 'FAILURE' });
  });

  it('inactive user returns generic 401 and logs failed login', async () => {
    mockFindByUsername.mockResolvedValue({ ...activeUser, is_active: 0 });
    mockVerifyPassword.mockResolvedValue(true);
    const { app } = makeApp();

    const res = await request(app).post('/api/auth/login').send({ username: 'admin', password: 'admin123' });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ message: 'Nama pengguna atau kata sandi salah' });
    expect(mockLogActivity).toHaveBeenCalledWith({ userId: 1, activity: 'LOGIN', result: 'FAILURE' });
  });

  it('unknown user returns generic 401 without DB log', async () => {
    mockFindByUsername.mockResolvedValue(null);
    const { app } = makeApp();

    const res = await request(app).post('/api/auth/login').send({ username: 'ghost', password: 'whatever' });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ message: 'Nama pengguna atau kata sandi salah' });
    expect(mockLogActivity).not.toHaveBeenCalled();
  });

  it('GET /api/auth/me returns 401 without session and 200 with session', async () => {
    mockFindByUsername.mockResolvedValue(activeUser);
    mockVerifyPassword.mockResolvedValue(true);
    mockFindById.mockResolvedValue(activeUser);
    const { app } = makeApp();

    const noSession = await request(app).get('/api/auth/me');
    expect(noSession.status).toBe(401);
    expect(noSession.body).toEqual({ message: 'Autentikasi diperlukan' });

    const agent = request.agent(app);
    const login = await agent.post('/api/auth/login').send({ username: 'admin', password: 'admin123' });
    expect(login.status).toBe(200);

    const me = await agent.get('/api/auth/me');
    expect(me.status).toBe(200);
    expect(me.body).toEqual({
      user: {
        id: 1,
        username: 'admin',
        role: 'admin',
        is_active: 1,
        created_at: '2026-01-01T00:00:00.000Z',
        updated_at: '2026-01-01T00:00:00.000Z',
      },
    });
  });

  it('logout clears session', async () => {
    mockFindByUsername.mockResolvedValue(activeUser);
    mockVerifyPassword.mockResolvedValue(true);
    mockFindById.mockResolvedValue(activeUser);
    const { app } = makeApp();
    const agent = request.agent(app);

    await agent.post('/api/auth/login').send({ username: 'admin', password: 'admin123' }).expect(200);
    const logout = await agent.post('/api/auth/logout');
    expect(logout.status).toBe(200);
    expect(logout.body).toEqual({ message: 'Logout berhasil' });
    expect(mockLogActivity).toHaveBeenCalledWith(expect.objectContaining({ activity: 'LOGOUT', result: 'SUCCESS' }));

    const me = await agent.get('/api/auth/me');
    expect(me.status).toBe(401);
  });
});
