import bcrypt from 'bcrypt';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULT_USERS = [
  { username: 'admin', password: 'admin123', role: 'admin' },
  { username: 'pegawai1', password: 'pegawai123', role: 'pegawai' },
  { username: 'pegawai2', password: 'pegawai123', role: 'pegawai' },
];

export async function seed(pool, users = DEFAULT_USERS) {
  for (const user of users) {
    const [rows] = await pool.query('SELECT id FROM users WHERE username = ? LIMIT 1', [user.username]);
    if (rows.length > 0) continue;

    const passwordHash = await bcrypt.hash(user.password, 10);
    await pool.query(
      'INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, 1)',
      [user.username, passwordHash, user.role],
    );
  }
}

async function runCli() {
  const { getPool, closePool } = await import('../config/db.js');
  const pool = getPool();
  try {
    await seed(pool);
    console.log('Database seed completed');
  } finally {
    await closePool();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCli().catch((error) => {
    console.error('Database seed failed');
    console.error(error.message);
    process.exitCode = 1;
  });
}
