import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.resolve(__dirname, './schema.sql');

function splitStatements(sql) {
  return sql
    .split(/;\s*(?:\r?\n|$)/)
    .map((statement) => statement.trim())
    .filter(Boolean);
}

export async function migrate(pool) {
  const sql = await fs.readFile(schemaPath, 'utf8');
  const statements = splitStatements(sql);
  for (const statement of statements) {
    await pool.query(statement);
  }
}

async function runCli() {
  const { getPool, closePool } = await import('../config/db.js');
  const pool = getPool();
  try {
    await migrate(pool);
    console.log('Database migration completed');
  } finally {
    await closePool();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCli().catch((error) => {
    console.error('Database migration failed');
    console.error(error.message);
    process.exitCode = 1;
  });
}
