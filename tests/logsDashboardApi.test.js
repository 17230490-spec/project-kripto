import request from 'supertest';
import session from 'express-session';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockFindByUsername = vi.fn();
const mockFindById = vi.fn();
const mockVerifyPassword = vi.fn();
const mockLogActivity = vi.fn();
const mockListActivityLogs = vi.fn();
const mockGetDashboard = vi.fn();

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
  listActivityLogs: mockListActivityLogs,
}));

vi.mock('../src/services/dashboard.js', () => ({
  getDashboard: mockGetDashboard,
}));

const { createApp } = await import('../src/app.js');

function makeApp() {
  return createApp({ sessionStore: new session.MemoryStore() });
}

const adminUser = {
  id: 1,
  username: 'admin',
  password_hash: '$2b$12$hashed',
  role: 'admin',
  is_active: 1,
  created_at: '2026-01-01T00:00:00.000Z',
  updated_at: '2026-01-01T00:00:00.000Z',
};

const pegawaiUser = {
  id: 2,
  username: 'pegawai',
  password_hash: '$2b$12$hashed',
  role: 'pegawai',
  is_active: 1,
  created_at: '2026-01-01T00:00:00.000Z',
  updated_at: '2026-01-01T00:00:00.000Z',
};

async function loginAs(app, user) {
  mockFindByUsername.mockResolvedValueOnce(user);
  mockVerifyPassword.mockResolvedValueOnce(true);
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ username: user.username, password: 'password123' });
  expect(res.status).toBe(200);
  mockFindById.mockImplementation(async (id) => {
    if (id === adminUser.id) return adminUser;
    if (id === pegawaiUser.id) return pegawaiUser;
    if (id === user.id) return user;
    return null;
  });
  return agent;
}

describe('GET /api/logs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
  });

  it('requires authentication', async () => {
    const app = makeApp();
    const res = await request(app).get('/api/logs');
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ message: 'Autentikasi diperlukan' });
  });

  it('forbids pegawai', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    const res = await agent.get('/api/logs');
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: 'Akses ditolak' });
    expect(mockListActivityLogs).not.toHaveBeenCalled();
  });

  it('admin can list logs with expected fields', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockListActivityLogs.mockResolvedValue([
      {
        id: 1,
        user_id: 2,
        username: 'pegawai',
        archive_id: 10,
        original_name: 'laporan.pdf',
        activity: 'UPLOAD_ARCHIVE',
        result: 'SUCCESS',
        created_at: '2026-11-21T10:00:00.000Z',
      },
    ]);

    const res = await agent.get('/api/logs');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      logs: [
        {
          id: 1,
          user_id: 2,
          username: 'pegawai',
          archive_id: 10,
          original_name: 'laporan.pdf',
          activity: 'UPLOAD_ARCHIVE',
          result: 'SUCCESS',
          created_at: '2026-11-21T10:00:00.000Z',
        },
      ],
    });
    expect(mockListActivityLogs).toHaveBeenCalledWith({ tanggal: undefined, userId: undefined });
  });

  it('admin can filter by tanggal and userId', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockListActivityLogs.mockResolvedValue([]);

    const res = await agent.get('/api/logs?tanggal=2026-11-21&userId=2');

    expect(res.status).toBe(200);
    expect(mockListActivityLogs).toHaveBeenCalledWith({ tanggal: '2026-11-21', userId: 2 });
  });

  it('rejects invalid userId filter', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);

    const res = await agent.get('/api/logs?userId=abc');

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ message: 'userId tidak valid' });
    expect(mockListActivityLogs).not.toHaveBeenCalled();
  });
});

describe('activity logging integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
  });

  it('records login and logout activities', async () => {
    const app = makeApp();
    mockFindByUsername.mockResolvedValue(adminUser);
    mockVerifyPassword.mockResolvedValue(true);
    mockFindById.mockResolvedValue(adminUser);
    const agent = request.agent(app);

    await agent.post('/api/auth/login').send({ username: 'admin', password: 'password123' }).expect(200);
    await agent.post('/api/auth/logout').expect(200);

    expect(mockLogActivity).toHaveBeenCalledWith(expect.objectContaining({ activity: 'LOGIN', result: 'SUCCESS' }));
    expect(mockLogActivity).toHaveBeenCalledWith(expect.objectContaining({ activity: 'LOGOUT', result: 'SUCCESS' }));
  });
});

describe('GET /api/dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
  });

  it('requires authentication', async () => {
    const app = makeApp();
    const res = await request(app).get('/api/dashboard');
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ message: 'Autentikasi diperlukan' });
  });

  it('returns archiveCount and recentActivities for admin (global scope)', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockGetDashboard.mockResolvedValue({
      archiveCount: 12,
      recentActivities: [
        { id: 9, activity: 'LOGIN', result: 'SUCCESS', created_at: '2026-11-21T10:00:00.000Z', username: 'admin' },
      ],
    });

    const res = await agent.get('/api/dashboard');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      archiveCount: 12,
      recentActivities: [
        { id: 9, activity: 'LOGIN', result: 'SUCCESS', created_at: '2026-11-21T10:00:00.000Z', username: 'admin' },
      ],
    });
    expect(mockGetDashboard).toHaveBeenCalledWith({ user: expect.objectContaining({ id: 1, role: 'admin' }) });
  });

  it('returns scoped dashboard for pegawai (own activities)', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    mockGetDashboard.mockResolvedValue({ archiveCount: 3, recentActivities: [] });

    const res = await agent.get('/api/dashboard');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ archiveCount: 3, recentActivities: [] });
    expect(mockGetDashboard).toHaveBeenCalledWith({ user: expect.objectContaining({ id: 2, role: 'pegawai' }) });
  });
});
