import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createArchiveRecord,
  deleteArchiveRecord,
  getArchiveById,
  listArchives,
} from '../src/services/archives.js';

function mockPool(queryResult = []) {
  return {
    query: vi.fn().mockResolvedValue([queryResult, []]),
  };
}

describe('archives service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('createArchiveRecord inserts expected fields and returns id', async () => {
    const pool = mockPool({ insertId: 42, affectedRows: 1 });
    const record = {
      userId: 7,
      originalName: 'laporan.pdf',
      storedName: 'abc.enc',
      fileExt: '.pdf',
      originalSize: 100,
      encryptedSize: 128,
      sha256: 'a'.repeat(64),
      salt: 'b'.repeat(32),
      iv: 'c'.repeat(32),
    };

    const id = await createArchiveRecord(record, pool);

    expect(id).toBe(42);
    expect(pool.query).toHaveBeenCalledTimes(1);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/INSERT INTO archives/i);
    expect(params).toEqual([
      7,
      'laporan.pdf',
      'abc.enc',
      '.pdf',
      100,
      128,
      'a'.repeat(64),
      'b'.repeat(32),
      'c'.repeat(32),
    ]);
  });

  it('listArchives filters by user_id for pegawai and selects DTO fields only', async () => {
    const rows = [{ id: 1, original_name: 'a.pdf' }];
    const pool = mockPool(rows);

    const result = await listArchives({ user: { id: 5, role: 'pegawai' } }, pool);

    expect(result).toBe(rows);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/WHERE/i);
    expect(sql).toMatch(/user_id\s*=\s*\?/i);
    expect(sql).not.toMatch(/\ba\.stored_name\b/i);
    expect(sql).not.toMatch(/\ba\.sha256\b/i);
    expect(sql).not.toMatch(/\ba\.salt\b/i);
    expect(sql).not.toMatch(/\ba\.iv\b/i);
    expect(params).toContain(5);
  });

  it('listArchives returns all for admin', async () => {
    const rows = [{ id: 1 }, { id: 2 }];
    const pool = mockPool(rows);

    const result = await listArchives({ user: { id: 1, role: 'admin' } }, pool);

    expect(result).toBe(rows);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).not.toMatch(/user_id\s*=\s*\?/i);
    expect(params).toEqual([]);
  });

  it('listArchives supports search by name and date', async () => {
    const pool = mockPool([]);
    await listArchives(
      { user: { id: 1, role: 'admin' }, q: 'laporan', tanggal: '2026-11-21' },
      pool,
    );

    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/original_name\s+LIKE\s+\?/i);
    expect(sql).toMatch(/DATE\(.*created_at.*\)\s*=\s*\?|created_at\s*>=|DATE\(created_at\)/i);
    expect(params).toContain('%laporan%');
    expect(params).toContain('2026-11-21');
  });

  it('listArchives for pegawai combines user filter with search', async () => {
    const pool = mockPool([]);
    await listArchives(
      { user: { id: 9, role: 'pegawai' }, q: 'doc', tanggal: '2026-01-01' },
      pool,
    );

    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/user_id\s*=\s*\?/i);
    expect(sql).toMatch(/original_name\s+LIKE\s+\?/i);
    expect(params).toEqual(expect.arrayContaining([9, '%doc%', '2026-01-01']));
  });

  it('listArchives rejects missing or invalid user context', async () => {
    const pool = mockPool([]);
    const badCases = [
      {},
      { user: null },
      { user: { role: 'pegawai' } },
      { user: { id: '5', role: 'pegawai' } },
      { user: { id: 0, role: 'pegawai' } },
      { user: { id: 1, role: 'owner' } },
      { user: { id: 1 } },
    ];

    for (const input of badCases) {
      await expect(listArchives(input, pool)).rejects.toMatchObject({ statusCode: 400 });
    }
    expect(pool.query).not.toHaveBeenCalled();
  });

  it('getArchiveById returns record or null', async () => {
    const row = { id: 3, original_name: 'x.pdf' };
    const pool = mockPool([row]);
    const found = await getArchiveById(3, pool);
    expect(found).toEqual(row);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/WHERE\s+a\.id\s*=\s*\?/i);
    expect(params).toEqual([3]);

    const pool2 = mockPool([]);
    const missing = await getArchiveById(999, pool2);
    expect(missing).toBeNull();
  });

  it('deleteArchiveRecord deletes by id and returns affected status', async () => {
    const pool = mockPool({ affectedRows: 1 });
    const ok = await deleteArchiveRecord(10, pool);
    expect(ok).toBe(true);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/DELETE FROM archives/i);
    expect(params).toEqual([10]);

    const pool2 = mockPool({ affectedRows: 0 });
    const miss = await deleteArchiveRecord(11, pool2);
    expect(miss).toBe(false);
  });
});
