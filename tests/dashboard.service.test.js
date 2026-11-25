import { describe, expect, it, vi } from 'vitest';
import { getDashboard } from '../src/services/dashboard.js';

function mockPool(responses) {
  const query = vi.fn();
  responses.forEach((rows) => query.mockResolvedValueOnce([rows]));
  return { query };
}

describe('dashboard service', () => {
  it('returns global archiveCount and recent 5 activities for admin', async () => {
    const pool = mockPool([
      [{ count: 12 }],
      [{ id: 1, activity: 'LOGIN', result: 'SUCCESS' }],
    ]);

    const data = await getDashboard({ user: { id: 1, role: 'admin' } }, pool);

    expect(data).toEqual({ archiveCount: 12, recentActivities: [{ id: 1, activity: 'LOGIN', result: 'SUCCESS' }] });
    expect(pool.query).toHaveBeenCalledTimes(2);
    const [countSql, countParams] = pool.query.mock.calls[0];
    expect(countSql).toMatch(/COUNT\(/i);
    expect(countSql).toMatch(/FROM archives/i);
    expect(countParams).toEqual([]);
    const [actSql, actParams] = pool.query.mock.calls[1];
    expect(actSql).toMatch(/FROM activity_logs/i);
    expect(actSql).toMatch(/LIMIT 5/i);
    expect(actParams).toEqual([]);
  });

  it('scopes archiveCount and recent activities to pegawai', async () => {
    const pool = mockPool([
      [{ count: 3 }],
      [{ id: 2, activity: 'UPLOAD_ARCHIVE', result: 'SUCCESS', user_id: 7 }],
    ]);

    const data = await getDashboard({ user: { id: 7, role: 'pegawai' } }, pool);

    expect(data.archiveCount).toBe(3);
    const [countSql, countParams] = pool.query.mock.calls[0];
    expect(countSql).toMatch(/WHERE/i);
    expect(countSql).toMatch(/user_id\s*=\s*\?/i);
    expect(countParams).toEqual([7]);
    const [actSql, actParams] = pool.query.mock.calls[1];
    expect(actSql).toMatch(/WHERE/i);
    expect(actSql).toMatch(/user_id\s*=\s*\?/i);
    expect(actSql).toMatch(/LIMIT 5/i);
    expect(actParams).toEqual([7]);
  });

  it('rejects invalid user context', async () => {
    const pool = mockPool([]);
    await expect(getDashboard({ user: null }, pool)).rejects.toMatchObject({ statusCode: 400 });
    expect(pool.query).not.toHaveBeenCalled();
  });
});
