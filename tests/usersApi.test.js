import request from 'supertest';
import session from 'express-session';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockFindByUsername = vi.fn();
const mockFindById = vi.fn();
const mockVerifyPassword = vi.fn();
const mockListUsers = vi.fn();
const mockCreateUser = vi.fn();
const mockUpdateUser = vi.fn();
const mockLogActivity = vi.fn();

vi.mock('../src/services/users.js', async () => {
  const actual = await vi.importActual('../src/services/users.js');
  return {
    ...actual,
    findByUsername: mockFindByUsername,
    findById: mockFindById,
    verifyPassword: mockVerifyPassword,
    listUsers: mockListUsers,
    createUser: mockCreateUser,
    updateUser: mockUpdateUser,
  };
});

vi.mock('../src/services/activityLogs.js', () => ({
  logActivity: mockLogActivity,
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

async function loginAs(app, user, password = 'password123') {
  mockFindByUsername.mockResolvedValueOnce(user);
  mockVerifyPassword.mockResolvedValueOnce(true);
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ username: user.username, password });
  expect(res.status).toBe(200);
  mockFindById.mockImplementation(async (id) => {
    if (id === user.id) return user;
    if (id === adminUser.id) return adminUser;
    if (id === pegawaiUser.id) return pegawaiUser;
    return null;
  });
  return agent;
}

describe('users API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
  });

  it('admin can list users without password_hash', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockListUsers.mockResolvedValue([
      { id: 1, username: 'admin', role: 'admin', is_active: 1 },
      { id: 2, username: 'pegawai', role: 'pegawai', is_active: 1 },
    ]);

    const res = await agent.get('/api/users');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      users: [
        { id: 1, username: 'admin', role: 'admin', is_active: 1 },
        { id: 2, username: 'pegawai', role: 'pegawai', is_active: 1 },
      ],
    });
    expect(JSON.stringify(res.body)).not.toContain('password_hash');
    expect(mockListUsers).toHaveBeenCalled();
  });

  it('admin can create user and password_hash is never returned', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockCreateUser.mockResolvedValue({
      id: 3,
      username: 'baru',
      role: 'pegawai',
      is_active: 1,
      created_at: '2026-01-02T00:00:00.000Z',
      updated_at: '2026-01-02T00:00:00.000Z',
    });

    const res = await agent.post('/api/users').send({
      username: 'baru',
      password: 'password123',
      role: 'pegawai',
    });

    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({ id: 3, username: 'baru', role: 'pegawai', is_active: 1 });
    expect(res.body.user).not.toHaveProperty('password_hash');
    expect(mockCreateUser).toHaveBeenCalledWith({
      username: 'baru',
      password: 'password123',
      role: 'pegawai',
    });
  });

  it('admin can update and deactivate user', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockUpdateUser.mockResolvedValue({
      id: 2,
      username: 'pegawai',
      role: 'pegawai',
      is_active: 0,
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-02T00:00:00.000Z',
    });

    const res = await agent.patch('/api/users/2').send({ is_active: false });

    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ id: 2, is_active: 0 });
    expect(res.body.user).not.toHaveProperty('password_hash');
    expect(mockUpdateUser).toHaveBeenCalledWith(2, { is_active: false });
  });

  it('pegawai gets 403 on user management endpoints', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);

    const list = await agent.get('/api/users');
    const create = await agent.post('/api/users').send({ username: 'x', password: 'password123', role: 'pegawai' });
    const patch = await agent.patch('/api/users/1').send({ is_active: false });

    expect(list.status).toBe(403);
    expect(create.status).toBe(403);
    expect(patch.status).toBe(403);
    expect(list.body).toEqual({ message: 'Akses ditolak' });
  });

  it('inactive user cannot login', async () => {
    const app = makeApp();
    mockFindByUsername.mockResolvedValue({ ...pegawaiUser, is_active: 0 });
    mockVerifyPassword.mockResolvedValue(true);

    const res = await request(app).post('/api/auth/login').send({ username: 'pegawai', password: 'password123' });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ message: 'Nama pengguna atau kata sandi salah' });
  });

  it('validates create payload', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockCreateUser.mockRejectedValue(Object.assign(new Error('Username sudah digunakan'), { statusCode: 409 }));

    const shortPw = await agent.post('/api/users').send({ username: 'u1', password: 'short', role: 'pegawai' });
    expect(shortPw.status).toBe(400);

    const badRole = await agent.post('/api/users').send({ username: 'u1', password: 'password123', role: 'owner' });
    expect(badRole.status).toBe(400);

    const dup = await agent.post('/api/users').send({ username: 'u1', password: 'password123', role: 'pegawai' });
    expect(dup.status).toBe(409);
  });

  it('rejects invalid patch fields and validates patch values', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);

    const badField = await agent.patch('/api/users/2').send({ password_hash: 'x' });
    expect(badField.status).toBe(400);

    const badRole = await agent.patch('/api/users/2').send({ role: 'owner' });
    expect(badRole.status).toBe(400);

    const badActive = await agent.patch('/api/users/2').send({ is_active: 'yes' });
    expect(badActive.status).toBe(400);

    const shortPw = await agent.patch('/api/users/2').send({ password: 'short' });
    expect(shortPw.status).toBe(400);

    expect(mockUpdateUser).not.toHaveBeenCalled();
  });
});
