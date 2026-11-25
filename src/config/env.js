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

const DEFAULT_CORS_ORIGINS = [
  'https://fe-kripto.vercel.app',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
];

function parseOrigins(value) {
  if (value === undefined || value === null || value === '') return DEFAULT_CORS_ORIGINS;
  const origins = String(value)
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  return origins.length > 0 ? origins : DEFAULT_CORS_ORIGINS;
}

export function loadEnv(source = process.env) {
  const nodeEnv = source.NODE_ENV ?? 'development';
  const sessionSecret = source.SESSION_SECRET;
  requiredInProduction('SESSION_SECRET', sessionSecret, nodeEnv);

  const cookieSecure =
    nodeEnv === 'production' ? true : toBool(source.COOKIE_SECURE, false);
  const cookieSameSite = nodeEnv === 'production' ? 'none' : 'lax';

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
    COOKIE_SAME_SITE: cookieSameSite,
    CORS_ORIGIN: parseOrigins(source.CORS_ORIGIN),
  };
}

export const env = loadEnv();
