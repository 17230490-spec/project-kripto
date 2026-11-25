import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { env } from '../config/env.js';

const STORED_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\.enc$/;

function storageError(message, statusCode = 400) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function resolveStoredPath(baseDir, storedName) {
  if (typeof storedName !== 'string' || !STORED_NAME_PATTERN.test(storedName)) {
    throw storageError('Nama berkas penyimpanan tidak valid');
  }
  if (storedName.includes('..') || storedName.includes('/') || storedName.includes('\\')) {
    throw storageError('Nama berkas penyimpanan tidak valid');
  }

  const resolvedBase = path.resolve(baseDir);
  const absolutePath = path.resolve(resolvedBase, storedName);
  const relative = path.relative(resolvedBase, absolutePath);
  if (relative.startsWith('..') || path.isAbsolute(relative) || path.basename(absolutePath) !== storedName) {
    throw storageError('Nama berkas penyimpanan tidak valid');
  }

  return { absolutePath, resolvedBase };
}

export function createStorageService(baseDir) {
  const resolvedBase = path.resolve(baseDir);

  async function ensureDir() {
    await fs.mkdir(resolvedBase, { recursive: true });
  }

  async function saveEncrypted(buffer) {
    await ensureDir();
    const data = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer ?? []);
    const storedName = `${randomUUID()}.enc`;
    const absolutePath = path.join(resolvedBase, storedName);
    await fs.writeFile(absolutePath, data);
    return {
      storedName,
      encryptedSize: data.length,
      absolutePath,
    };
  }

  async function readEncrypted(storedName) {
    await ensureDir();
    const { absolutePath } = resolveStoredPath(resolvedBase, storedName);
    return fs.readFile(absolutePath);
  }

  async function deleteEncrypted(storedName) {
    await ensureDir();
    const { absolutePath } = resolveStoredPath(resolvedBase, storedName);
    await fs.unlink(absolutePath);
  }

  return {
    baseDir: resolvedBase,
    ensureDir,
    saveEncrypted,
    readEncrypted,
    deleteEncrypted,
  };
}

const defaultStorage = createStorageService(env.STORAGE_PATH);

export const saveEncrypted = (buffer) => defaultStorage.saveEncrypted(buffer);
export const readEncrypted = (storedName) => defaultStorage.readEncrypted(storedName);
export const deleteEncrypted = (storedName) => defaultStorage.deleteEncrypted(storedName);
export const ensureStorageDir = () => defaultStorage.ensureDir();
export const storage = defaultStorage;
