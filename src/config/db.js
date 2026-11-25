import mysql from 'mysql2/promise';
import { env } from './env.js';

export let pool;

export function createPoolFromEnv(source = env) {
  return mysql.createPool({
    host: source.DB_HOST,
    port: source.DB_PORT,
    user: source.DB_USER,
    password: source.DB_PASSWORD,
    database: source.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    namedPlaceholders: true,
  });
}

export function getPool() {
  if (!pool) {
    pool = createPoolFromEnv(env);
  }
  return pool;
}

export async function closePool() {
  if (pool) {
    await pool.end();
    pool = undefined;
  }
}
