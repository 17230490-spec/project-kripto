import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const defaultStoragePath = path.resolve(__dirname, '../../storage');

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

function requiredInProduction(name, value, nodeEnv) {
  if (nodeEnv === 'production' && !value) {
    throw new Error(`${name} is required in production`);
  }
}

function toInt(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toBool(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

export function loadEnv(source = process.env) {
  const nodeEnv = source.NODE_ENV ?? 'development';
  const sessionSecret = source.SESSION_SECRET;
  requiredInProduction('SESSION_SECRET', sessionSecret, nodeEnv);

  const cookieSecure =
    nodeEnv === 'production' ? true : toBool(source.COOKIE_SECURE, false);

  return {
    PORT: toInt(source.PORT, 3000),
    NODE_ENV: nodeEnv,
    DB_HOST: source.DB_HOST ?? '127.0.0.1',
    DB_PORT: toInt(source.DB_PORT, 3306),
    DB_USER: source.DB_USER ?? 'root',
    DB_PASSWORD: source.DB_PASSWORD ?? '',
    DB_NAME: source.DB_NAME ?? 'arsip_digital',
    SESSION_SECRET: sessionSecret ?? 'dev-insecure-session-secret',
    STORAGE_PATH: source.STORAGE_PATH ? path.resolve(source.STORAGE_PATH) : defaultStoragePath,
    COOKIE_SECURE: cookieSecure,
  };
}

export const env = loadEnv();
