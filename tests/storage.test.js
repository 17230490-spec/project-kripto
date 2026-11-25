import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createStorageService } from '../src/services/storage.js';

describe('storage service', () => {
  let tempDir;
  let storage;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'arsip-storage-'));
    storage = createStorageService(tempDir);
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('saveEncrypted generates random .enc name and writes inside storage dir', async () => {
    const data = Buffer.from('encrypted-content');
    const result = await storage.saveEncrypted(data);

    expect(result.storedName).toMatch(/^[a-f0-9-]{36}\.enc$/);
    expect(result.encryptedSize).toBe(data.length);
    expect(result.absolutePath).toBe(path.join(tempDir, result.storedName));
    expect(path.dirname(result.absolutePath)).toBe(path.resolve(tempDir));

    const written = await fs.readFile(result.absolutePath);
    expect(written.equals(data)).toBe(true);
  });

  it('saveEncrypted creates storage dir if missing', async () => {
    const nested = path.join(tempDir, 'nested', 'storage');
    const nestedStorage = createStorageService(nested);
    const result = await nestedStorage.saveEncrypted(Buffer.from('x'));
    const stat = await fs.stat(nested);
    expect(stat.isDirectory()).toBe(true);
    expect(result.absolutePath.startsWith(path.resolve(nested))).toBe(true);
  });

  it('saveEncrypted generates different names for same content', async () => {
    const data = Buffer.from('same');
    const a = await storage.saveEncrypted(data);
    const b = await storage.saveEncrypted(data);
    expect(a.storedName).not.toBe(b.storedName);
  });

  it('readEncrypted reads stored file', async () => {
    const data = Buffer.from('read-me');
    const { storedName } = await storage.saveEncrypted(data);
    const read = await storage.readEncrypted(storedName);
    expect(read.equals(data)).toBe(true);
  });

  it('deleteEncrypted removes stored file', async () => {
    const { storedName, absolutePath } = await storage.saveEncrypted(Buffer.from('delete-me'));
    await storage.deleteEncrypted(storedName);
    await expect(fs.access(absolutePath)).rejects.toThrow();
  });

  it('rejects path traversal names on read/delete', async () => {
    const badNames = [
      '../secret.enc',
      '..\\secret.enc',
      '/etc/passwd',
      'foo/../../secret.enc',
      'subdir/file.enc',
      '..',
      '.',
      '',
    ];

    for (const name of badNames) {
      await expect(storage.readEncrypted(name)).rejects.toMatchObject({ statusCode: 400 });
      await expect(storage.deleteEncrypted(name)).rejects.toMatchObject({ statusCode: 400 });
    }
  });

  it('rejects non-.enc stored names', async () => {
    await expect(storage.readEncrypted('file.txt')).rejects.toMatchObject({ statusCode: 400 });
    await expect(storage.deleteEncrypted('file.txt')).rejects.toMatchObject({ statusCode: 400 });
  });
});
