import { describe, expect, it, vi } from 'vitest';
import fs from 'node:fs/promises';

vi.mock('mysql2/promise', () => ({
  default: {
    createPool: vi.fn(() => ({ mocked: true, query: vi.fn(), end: vi.fn() })),
  },
}));

describe('db helpers', () => {
  it('createPoolFromEnv uses env config', async () => {
    const mysql = (await import('mysql2/promise')).default;
    const { createPoolFromEnv } = await import('../src/config/db.js');
    const pool = createPoolFromEnv({
      DB_HOST: 'db.local',
      DB_PORT: 3307,
      DB_USER: 'u',
      DB_PASSWORD: 'p',
      DB_NAME: 'arsip',
    });
    expect(mysql.createPool).toHaveBeenCalledWith({
      host: 'db.local',
      port: 3307,
      user: 'u',
      password: 'p',
      database: 'arsip',
      waitForConnections: true,
      connectionLimit: 10,
      namedPlaceholders: true,
    });
    expect(pool).toEqual({ mocked: true, query: expect.any(Function), end: expect.any(Function) });
  });

  it('migrate executes schema SQL statements', async () => {
    const { migrate } = await import('../src/db/migrate.js');
    const query = vi.fn().mockResolvedValue([{}]);
    const pool = { query };
    await migrate(pool);
    expect(query).toHaveBeenCalled();
    const sqlArg = query.mock.calls.map((c) => c[0]).join('\n');
    expect(sqlArg).toMatch(/CREATE TABLE IF NOT EXISTS users/i);
    expect(sqlArg).toMatch(/CREATE TABLE IF NOT EXISTS archives/i);
    expect(sqlArg).toMatch(/CREATE TABLE IF NOT EXISTS activity_logs/i);
  });

  it('seed inserts admin and 2 pegawai when missing and does not log passwords', async () => {
    const { seed } = await import('../src/db/seed.js');
    const query = vi.fn().mockResolvedValue([[]]);
    const pool = { query };
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});

    await seed(pool);

    const calls = query.mock.calls.map((c) => c[0] + ' ' + JSON.stringify(c[1] ?? []));
    const joined = calls.join('\n');
    expect(joined).toMatch(/admin/i);
    expect(joined).toMatch(/pegawai/i);
    expect(joined.match(/INSERT|insert/g)?.length ?? 0).toBeGreaterThanOrEqual(3);

    const logged = [...logSpy.mock.calls, ...infoSpy.mock.calls].flat().join(' ');
    expect(logged).not.toMatch(/admin123|pegawai123|password/i);
    logSpy.mockRestore();
    infoSpy.mockRestore();
  });

  it('seed skips existing users', async () => {
    const { seed, DEFAULT_USERS } = await import('../src/db/seed.js');
    const query = vi.fn().mockImplementation(async (sql, params) => {
      if (/SELECT/i.test(sql)) return [[{ username: params[0] }]];
      return [{}];
    });
    const pool = { query };
    await seed(pool);
    const insertCalls = query.mock.calls.filter((c) => /INSERT/i.test(c[0]));
    expect(insertCalls).toHaveLength(0);
    expect(DEFAULT_USERS).toHaveLength(3);
  });
});
