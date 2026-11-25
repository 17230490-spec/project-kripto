import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  ArchiveCryptoError,
  decryptArchive,
  decryptArchiveWithKeys,
  deriveKeys,
  encryptArchive,
  sha256Hex,
} from '../src/services/archiveCrypto.js';

const PASSWORD = 'kunci-rahasia-123';

describe('archiveCrypto', () => {
  it('round-trip enkripsi lalu dekripsi menghasilkan byte identik (PDF, biner, 100 KB)', async () => {
    const samples = [
      Buffer.from('%PDF-1.7\n%contoh arsip perusahaan\n', 'utf8'),
      Buffer.from(Array.from({ length: 256 }, (_, i) => i)),
      randomBytes(100 * 1024),
    ];

    for (const original of samples) {
      const result = await encryptArchive({ data: original, password: PASSWORD });
      expect(result.salt).toMatch(/^[0-9a-f]{32}$/);
      expect(result.iv).toMatch(/^[0-9a-f]{32}$/);
      expect(result.sha256).toBe(sha256Hex(original));
      expect(result.encrypted.length % 16).toBe(0);
      expect(result.encrypted.toString('latin1')).not.toContain('%PDF');

      const restored = await decryptArchive({
        encrypted: result.encrypted,
        salt: result.salt,
        iv: result.iv,
        sha256: result.sha256,
        password: PASSWORD,
      });
      expect(restored.equals(original)).toBe(true);
    }
  });

  it('round-trip untuk berkas kosong', async () => {
    const original = Buffer.alloc(0);
    const result = await encryptArchive({ data: original, password: PASSWORD });
    const restored = await decryptArchive({ ...result, password: PASSWORD });
    expect(restored.length).toBe(0);
  });

  it('salt dan IV acak membuat dua enkripsi berkas sama menghasilkan ciphertext berbeda', async () => {
    const original = Buffer.from('%PDF-dua kali', 'utf8');
    const first = await encryptArchive({ data: original, password: PASSWORD });
    const second = await encryptArchive({ data: original, password: PASSWORD });
    expect(first.salt).not.toBe(second.salt);
    expect(first.iv).not.toBe(second.iv);
    expect(first.encrypted.equals(second.encrypted)).toBe(false);
  });

  it('penurunan kunci PBKDF2-HMAC-SHA256 100.000 iterasi 32 byte sesuai node:crypto', async () => {
    const salt = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
    const expected = pbkdf2Sync(PASSWORD, salt, 100000, 32, 'sha256');
    const { aesKey, playfairKeyword, derived } = await deriveKeys(PASSWORD, salt);
    expect(derived.equals(expected)).toBe(true);
    expect(aesKey.equals(expected.subarray(0, 16))).toBe(true);
    expect(playfairKeyword).toHaveLength(16);
    expect(playfairKeyword).toMatch(/^[A-Z]{16}$/);
  });

  it('kunci salah ditolak dengan pesan "Kunci salah atau berkas rusak" tanpa crash', async () => {
    const original = Buffer.from('%PDF-kunci-salah', 'utf8');
    const result = await encryptArchive({ data: original, password: PASSWORD });

    for (let attempt = 0; attempt < 8; attempt += 1) {
      const wrongPassword = `${PASSWORD}-salah-${attempt}`;
      await expect(
        decryptArchive({ ...result, password: wrongPassword }),
      ).rejects.toMatchObject({ message: 'Kunci salah atau berkas rusak' });
    }
  });

  it('kunci salah yang lolos padding tetap ditolak saat huruf Playfair tidak valid', () => {
    const aesKey = randomBytes(16);
    const iv = randomBytes(16);
    const invalidLetterPlaintext = Buffer.alloc(16, 0x00);
    invalidLetterPlaintext[15] = 0x01;

    const cipher = createCipheriv('aes-128-cbc', aesKey, iv);
    const ciphertext = Buffer.concat([
      cipher.update(invalidLetterPlaintext),
      cipher.final(),
    ]);

    expect(() =>
      decryptArchiveWithKeys({
        encrypted: ciphertext,
        iv,
        aesKey,
        playfairKeyword: 'MONARCHY',
        sha256: '0'.repeat(64),
      }),
    ).toThrow(new ArchiveCryptoError('WRONG_KEY', 'Kunci salah atau berkas rusak'));
  });

  it('hash tidak cocok setelah dekripsi berhasil ditolak dengan "Arsip tidak utuh"', async () => {
    const original = Buffer.from('%PDF-integritas', 'utf8');
    const result = await encryptArchive({ data: original, password: PASSWORD });
    await expect(
      decryptArchive({ ...result, sha256: 'f'.repeat(64), password: PASSWORD }),
    ).rejects.toMatchObject({ message: 'Arsip tidak utuh' });
  });
});
