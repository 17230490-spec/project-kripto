import { describe, expect, it, vi } from 'vitest';
import { listActivityLogs, logActivity } from '../src/services/activityLogs.js';

function mockPool(rows = [], result = { insertId: 1 }) {
  return { query: vi.fn().mockResolvedValue([rows, result]) };
}

describe('activityLogs service', () => {
  it('logActivity inserts only user_id, archive_id, activity, result', async () => {
    const pool = mockPool();
    await logActivity({ userId: 2, archiveId: 10, activity: 'UPLOAD_ARCHIVE', result: 'SUCCESS' }, pool);

    expect(pool.query).toHaveBeenCalledTimes(1);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/INSERT INTO activity_logs/i);
    expect(sql).toMatch(/\(user_id, archive_id, activity, result\)/i);
    expect(params).toEqual([2, 10, 'UPLOAD_ARCHIVE', 'SUCCESS']);
  });

  it('logActivity defaults archiveId to null and ignores extra fields', async () => {
    const pool = mockPool();
    await logActivity({
      userId: 1,
      activity: 'LOGIN',
      result: 'SUCCESS',
      password: 'secret',
      key: 'abc',
      token: 'x',
    }, pool);

    const [, params] = pool.query.mock.calls[0];
    expect(params).toEqual([1, null, 'LOGIN', 'SUCCESS']);
  });

  it('listActivityLogs returns logs with user/archive info', async () => {
    const rows = [{ id: 1, activity: 'LOGIN', result: 'SUCCESS', username: 'admin' }];
    const pool = mockPool(rows);

    const logs = await listActivityLogs({}, pool);

    expect(logs).toEqual(rows);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/FROM activity_logs/i);
    expect(sql).toMatch(/JOIN users/i);
    expect(sql).toMatch(/ORDER BY/i);
    expect(params).toEqual([]);
  });

  it('listActivityLogs filters by tanggal and userId', async () => {
    const pool = mockPool([]);
    await listActivityLogs({ tanggal: '2026-11-21', userId: 7 }, pool);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/DATE\(.*created_at.*\)\s*=\s*\?/i);
    expect(sql).toMatch(/user_id\s*=\s*\?/i);
    expect(params).toEqual(expect.arrayContaining(['2026-11-21', 7]));
  });
});
