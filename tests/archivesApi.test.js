import request from 'supertest';
import session from 'express-session';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockFindByUsername = vi.fn();
const mockFindById = vi.fn();
const mockVerifyPassword = vi.fn();
const mockLogActivity = vi.fn();

const mockCreateArchiveRecord = vi.fn();
const mockListArchives = vi.fn();
const mockGetArchiveById = vi.fn();
const mockDeleteArchiveRecord = vi.fn();

const mockSaveEncrypted = vi.fn();
const mockReadEncrypted = vi.fn();
const mockDeleteEncrypted = vi.fn();

const mockEncryptFileContainer = vi.fn();
const mockDecryptFileContainer = vi.fn();
const mockParseContainer = vi.fn();

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

vi.mock('../src/services/archives.js', () => ({
  createArchiveRecord: mockCreateArchiveRecord,
  listArchives: mockListArchives,
  getArchiveById: mockGetArchiveById,
  deleteArchiveRecord: mockDeleteArchiveRecord,
}));

vi.mock('../src/services/storage.js', () => ({
  saveEncrypted: mockSaveEncrypted,
  readEncrypted: mockReadEncrypted,
  deleteEncrypted: mockDeleteEncrypted,
}));

vi.mock('../src/services/archiveContainer.js', async () => {
  const actual = await vi.importActual('../src/services/archiveContainer.js');
  return {
    ...actual,
    encryptFileContainer: mockEncryptFileContainer,
    decryptFileContainer: mockDecryptFileContainer,
    parseContainer: mockParseContainer,
  };
});

const { createApp } = await import('../src/app.js');
const { ContainerError } = await import('../src/services/archiveContainer.js');
const { ArchiveCryptoError } = await import('../src/services/archiveCrypto.js');
const { MAX_ORIGINAL_SIZE } = await import('../src/services/fileTypes.js');

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

function binaryParser(res, callback) {
  const chunks = [];
  res.on('data', (chunk) => chunks.push(chunk));
  res.on('end', () => callback(null, Buffer.concat(chunks)));
}

const PDF = Buffer.from('%PDF-1.7\n%kontrak\n', 'utf8');
const PASSWORD = 'kunci-rahasia-123';

const containerMeta = {
  format: 'arsip-digital',
  version: 1,
  originalName: 'laporan.pdf',
  fileExt: '.pdf',
  originalSize: PDF.length,
  encryptedSize: 128,
  sha256: 'a'.repeat(64),
  salt: 'b'.repeat(32),
  iv: 'c'.repeat(32),
};

describe('POST /api/archives', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
  });

  it('requires authentication', async () => {
    const app = makeApp();
    const res = await request(app).post('/api/archives');
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ message: 'Autentikasi diperlukan' });
  });

  it('authenticated upload creates DB record + .enc file and no plaintext on disk', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    const container = Buffer.from('encrypted-container');
    mockEncryptFileContainer.mockResolvedValue(container);
    mockParseContainer.mockReturnValue({ metadata: { ...containerMeta, encryptedSize: container.length }, ciphertext: container });
    mockSaveEncrypted.mockResolvedValue({ storedName: 'random.enc', encryptedSize: container.length, absolutePath: '/tmp/random.enc' });
    mockCreateArchiveRecord.mockResolvedValue(77);

    const res = await agent
      .post('/api/archives')
      .field('password', PASSWORD)
      .field('passwordConfirm', PASSWORD)
      .attach('file', PDF, { filename: 'laporan.pdf', contentType: 'application/pdf' });

    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ id: 77 });
    expect(mockEncryptFileContainer).toHaveBeenCalledWith(expect.objectContaining({
      password: PASSWORD,
      originalName: 'laporan.pdf',
    }));
    const encryptedArg = mockEncryptFileContainer.mock.calls[0][0].data;
    expect(Buffer.isBuffer(encryptedArg)).toBe(true);
    expect(Buffer.compare(encryptedArg, PDF)).toBe(0);
    expect(mockSaveEncrypted).toHaveBeenCalledTimes(1);
    expect(mockSaveEncrypted).toHaveBeenCalledWith(container);
    expect(mockCreateArchiveRecord).toHaveBeenCalledWith(expect.objectContaining({
      userId: pegawaiUser.id,
      originalName: 'laporan.pdf',
      storedName: 'random.enc',
      fileExt: '.pdf',
      originalSize: PDF.length,
      sha256: 'a'.repeat(64),
      salt: 'b'.repeat(32),
      iv: 'c'.repeat(32),
    }));
    // no plaintext on disk: only saveEncrypted called with container
    const saved = mockSaveEncrypted.mock.calls[0][0];
    expect(Buffer.compare(saved, PDF)).not.toBe(0);
  });

  it('rejects missing file', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    const res = await agent.post('/api/archives').field('password', PASSWORD).field('passwordConfirm', PASSWORD);
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ message: 'Berkas wajib dipilih' });
  });

  it('rejects short or mismatched password', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    const short = await agent.post('/api/archives').field('password', 'pendek').field('passwordConfirm', 'pendek')
      .attach('file', PDF, { filename: 'a.pdf' });
    expect(short.status).toBe(400);
    expect(short.body.message).toBe('Kunci minimal 8 karakter dan konfirmasi harus sama');

    const mismatch = await agent.post('/api/archives').field('password', PASSWORD).field('passwordConfirm', 'beda')
      .attach('file', PDF, { filename: 'a.pdf' });
    expect(mismatch.status).toBe(400);
    expect(mismatch.body.message).toBe('Kunci minimal 8 karakter dan konfirmasi harus sama');
  });

  it('rejects unsupported extension with PRD message', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    const res = await agent.post('/api/archives').field('password', PASSWORD).field('passwordConfirm', PASSWORD)
      .attach('file', Buffer.from('x'), { filename: 'skrip.exe' });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ message: 'Jenis atau ukuran berkas tidak didukung' });
  });

  it('rejects oversize file with 413 and PRD message', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    const res = await agent.post('/api/archives').field('password', PASSWORD).field('passwordConfirm', PASSWORD)
      .attach('file', Buffer.alloc(MAX_ORIGINAL_SIZE + 1, 1), { filename: 'besar.pdf' });
    expect(res.status).toBe(413);
    expect(res.body).toEqual({ message: 'Jenis atau ukuran berkas tidak didukung' });
  }, 15000);
});

describe('GET /api/archives', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
  });

  it('requires authentication', async () => {
    const app = makeApp();
    const res = await request(app).get('/api/archives');
    expect(res.status).toBe(401);
  });

  it('pegawai sees own archives only', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    mockListArchives.mockResolvedValue([{ id: 1, original_name: 'a.pdf', user_id: pegawaiUser.id }]);

    const res = await agent.get('/api/archives?q=lap&tanggal=2026-11-21');

    expect(res.status).toBe(200);
    expect(res.body.archives).toHaveLength(1);
    expect(mockListArchives).toHaveBeenCalledWith({
      user: expect.objectContaining({ id: pegawaiUser.id, role: 'pegawai' }),
      q: 'lap',
      tanggal: '2026-11-21',
    });
  });

  it('omits internal crypto/storage metadata from response', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockListArchives.mockResolvedValue([{
      id: 1,
      user_id: 2,
      original_name: 'a.pdf',
      file_ext: '.pdf',
      original_size: 10,
      encrypted_size: 20,
      created_at: '2026-01-01T00:00:00.000Z',
      username: 'pegawai',
    }]);

    const res = await agent.get('/api/archives');

    expect(res.status).toBe(200);
    expect(res.body.archives[0]).toEqual({
      id: 1,
      user_id: 2,
      original_name: 'a.pdf',
      file_ext: '.pdf',
      original_size: 10,
      encrypted_size: 20,
      created_at: '2026-01-01T00:00:00.000Z',
      username: 'pegawai',
    });
    expect(res.body.archives[0]).not.toHaveProperty('stored_name');
    expect(res.body.archives[0]).not.toHaveProperty('sha256');
    expect(res.body.archives[0]).not.toHaveProperty('salt');
    expect(res.body.archives[0]).not.toHaveProperty('iv');
  });

  it('admin sees all archives', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockListArchives.mockResolvedValue([{ id: 1 }, { id: 2 }]);

    const res = await agent.get('/api/archives');

    expect(res.status).toBe(200);
    expect(res.body.archives).toHaveLength(2);
    expect(mockListArchives).toHaveBeenCalledWith({
      user: expect.objectContaining({ id: adminUser.id, role: 'admin' }),
      q: undefined,
      tanggal: undefined,
    });
  });
});

describe('POST /api/archives/:id/download', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
  });

  it('requires authentication', async () => {
    const app = makeApp();
    const res = await request(app).post('/api/archives/1/download').send({ password: PASSWORD });
    expect(res.status).toBe(401);
  });

  it('returns original bytes and X-Integrity: verified', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    mockGetArchiveById.mockResolvedValue({
      id: 10,
      user_id: pegawaiUser.id,
      stored_name: 'x.enc',
      original_name: 'laporan.pdf',
      file_ext: '.pdf',
    });
    mockReadEncrypted.mockResolvedValue(Buffer.from('container'));
    mockDecryptFileContainer.mockResolvedValue({
      data: PDF,
      metadata: { originalName: 'laporan.pdf', fileExt: '.pdf', originalSize: PDF.length },
    });

    const res = await agent
      .post('/api/archives/10/download')
      .send({ password: PASSWORD })
      .buffer(true)
      .parse(binaryParser);

    expect(res.status).toBe(200);
    expect(res.headers['x-integrity']).toBe('verified');
    expect(res.headers['content-disposition']).toContain('laporan.pdf');
    expect(res.headers['content-type']).toContain('application/pdf');
    expect(Buffer.compare(res.body, PDF)).toBe(0);
    expect(mockReadEncrypted).toHaveBeenCalledWith('x.enc');
    expect(mockDecryptFileContainer).toHaveBeenCalledWith({
      container: Buffer.from('container'),
      password: PASSWORD,
    });
  });

  it('pegawai cannot download another user archive', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    mockGetArchiveById.mockResolvedValue({ id: 10, user_id: 999, stored_name: 'x.enc', original_name: 'a.pdf', file_ext: '.pdf' });

    const res = await agent.post('/api/archives/10/download').send({ password: PASSWORD });
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: 'Akses ditolak' });
    expect(mockReadEncrypted).not.toHaveBeenCalled();
  });

  it('admin can download any archive', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockGetArchiveById.mockResolvedValue({ id: 10, user_id: 999, stored_name: 'x.enc', original_name: 'a.pdf', file_ext: '.pdf' });
    mockReadEncrypted.mockResolvedValue(Buffer.from('container'));
    mockDecryptFileContainer.mockResolvedValue({ data: PDF, metadata: { originalName: 'a.pdf', fileExt: '.pdf' } });

    const res = await agent.post('/api/archives/10/download').send({ password: PASSWORD }).buffer(true).parse(binaryParser);
    expect(res.status).toBe(200);
  });

  it('maps wrong key to PRD message', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    mockGetArchiveById.mockResolvedValue({ id: 10, user_id: pegawaiUser.id, stored_name: 'x.enc', original_name: 'a.pdf', file_ext: '.pdf' });
    mockReadEncrypted.mockResolvedValue(Buffer.from('container'));
    mockDecryptFileContainer.mockRejectedValue(new ContainerError('WRONG_KEY', 'Kunci salah atau berkas rusak'));

    const res = await agent.post('/api/archives/10/download').send({ password: 'wrongpass123' });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ message: 'Kunci salah atau berkas rusak' });
  });

  it('maps corrupt/integrity failures to PRD messages', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    mockGetArchiveById.mockResolvedValue({ id: 10, user_id: pegawaiUser.id, stored_name: 'x.enc', original_name: 'a.pdf', file_ext: '.pdf' });
    mockReadEncrypted.mockResolvedValue(Buffer.from('container'));

    mockDecryptFileContainer.mockRejectedValueOnce(new ContainerError('INVALID_CONTAINER', 'Kunci salah atau berkas rusak'));
    const corrupt = await agent.post('/api/archives/10/download').send({ password: PASSWORD });
    expect(corrupt.status).toBe(400);
    expect(corrupt.body).toEqual({ message: 'Kunci salah atau berkas rusak' });

    mockReadEncrypted.mockResolvedValue(Buffer.from('container'));
    mockDecryptFileContainer.mockRejectedValueOnce(new ArchiveCryptoError('INTEGRITY', 'Arsip tidak utuh'));
    const integrity = await agent.post('/api/archives/10/download').send({ password: PASSWORD });
    expect(integrity.status).toBe(400);
    expect(integrity.body).toEqual({ message: 'Arsip tidak utuh' });
  });

  it('rejects short/missing password', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    const res = await agent.post('/api/archives/10/download').send({ password: 'short' });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ message: 'Kunci minimal 8 karakter' });
    expect(mockGetArchiveById).not.toHaveBeenCalled();
  });
});

describe('DELETE /api/archives/:id', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLogActivity.mockResolvedValue(undefined);
  });

  it('requires authentication', async () => {
    const app = makeApp();
    const res = await request(app).delete('/api/archives/1');
    expect(res.status).toBe(401);
  });

  it('owner can delete and file removed', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    mockGetArchiveById.mockResolvedValue({ id: 10, user_id: pegawaiUser.id, stored_name: 'x.enc' });
    mockDeleteEncrypted.mockResolvedValue(undefined);
    mockDeleteArchiveRecord.mockResolvedValue(true);

    const res = await agent.delete('/api/archives/10');
    expect(res.status).toBe(200);
    expect(mockDeleteArchiveRecord).toHaveBeenCalledWith(10);
    expect(mockDeleteEncrypted).toHaveBeenCalledWith('x.enc');
    expect(mockDeleteArchiveRecord.mock.invocationCallOrder[0]).toBeLessThan(mockDeleteEncrypted.mock.invocationCallOrder[0]);
  });

  it('admin can delete any archive', async () => {
    const app = makeApp();
    const agent = await loginAs(app, adminUser);
    mockGetArchiveById.mockResolvedValue({ id: 10, user_id: 999, stored_name: 'x.enc' });
    mockDeleteEncrypted.mockResolvedValue(undefined);
    mockDeleteArchiveRecord.mockResolvedValue(true);

    const res = await agent.delete('/api/archives/10');
    expect(res.status).toBe(200);
  });

  it('pegawai cannot delete another user archive', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    mockGetArchiveById.mockResolvedValue({ id: 10, user_id: 999, stored_name: 'x.enc' });

    const res = await agent.delete('/api/archives/10');
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ message: 'Akses ditolak' });
    expect(mockDeleteEncrypted).not.toHaveBeenCalled();
  });
  it('cleans up saved encrypted file when DB insert fails', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    const container = Buffer.from('encrypted-container');
    mockEncryptFileContainer.mockResolvedValue(container);
    mockParseContainer.mockReturnValue({ metadata: { ...containerMeta, encryptedSize: container.length }, ciphertext: container });
    mockSaveEncrypted.mockResolvedValue({ storedName: 'orphan.enc', encryptedSize: container.length, absolutePath: '/tmp/orphan.enc' });
    mockCreateArchiveRecord.mockRejectedValue(Object.assign(new Error('db fail'), { statusCode: 500 }));

    const res = await agent
      .post('/api/archives')
      .field('password', PASSWORD)
      .field('passwordConfirm', PASSWORD)
      .attach('file', PDF, { filename: 'laporan.pdf', contentType: 'application/pdf' });

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ message: 'Terjadi kesalahan pada server' });
    expect(mockSaveEncrypted).toHaveBeenCalledWith(container);
    expect(mockDeleteEncrypted).toHaveBeenCalledWith('orphan.enc');
  });

  it('tolerates ENOENT when deleting encrypted file after DB delete', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    mockGetArchiveById.mockResolvedValue({ id: 10, user_id: pegawaiUser.id, stored_name: 'missing.enc' });
    mockDeleteArchiveRecord.mockResolvedValue(true);
    mockDeleteEncrypted.mockRejectedValue(Object.assign(new Error('missing'), { code: 'ENOENT' }));

    const res = await agent.delete('/api/archives/10');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'Arsip berhasil dihapus' });
  });

  it('returns success with warning when file cleanup fails after DB delete', async () => {
    const app = makeApp();
    const agent = await loginAs(app, pegawaiUser);
    mockGetArchiveById.mockResolvedValue({ id: 10, user_id: pegawaiUser.id, stored_name: 'locked.enc' });
    mockDeleteArchiveRecord.mockResolvedValue(true);
    mockDeleteEncrypted.mockRejectedValue(Object.assign(new Error('permission denied'), { code: 'EPERM' }));

    const res = await agent.delete('/api/archives/10');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'Arsip berhasil dihapus, tetapi berkas terenkripsi gagal dibersihkan' });
  });

});
