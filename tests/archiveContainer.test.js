import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  CONTAINER_MAGIC,
  ContainerError,
  decryptFileContainer,
  encryptFileContainer,
  parseContainer,
} from '../src/services/archiveContainer.js';
import { MESSAGES } from '../src/services/archiveCrypto.js';
import { MAX_ORIGINAL_SIZE } from '../src/services/fileTypes.js';

const PASSWORD = 'kunci-rahasia-123';
const PDF = Buffer.from('%PDF-1.7\n%arsip perusahaan\n', 'utf8');

function containerFrom(meta, ciphertext) {
  const metaBuffer = Buffer.from(JSON.stringify(meta), 'utf8');
  const header = Buffer.alloc(13);
  Buffer.from(CONTAINER_MAGIC, 'ascii').copy(header, 0);
  header[8] = 1;
  header.writeUInt32BE(metaBuffer.length, 9);
  return Buffer.concat([header, metaBuffer, ciphertext]);
}

describe('archiveContainer', () => {
  it('membuat container .enc self-contained dengan metadata yang benar', async () => {
    const container = await encryptFileContainer({
      data: PDF,
      password: PASSWORD,
      originalName: 'laporan.pdf',
    });

    expect(container.subarray(0, 8).toString('ascii')).toBe(CONTAINER_MAGIC);
    expect(container[8]).toBe(1);

    const { metadata, ciphertext } = parseContainer(container);
    expect(metadata.originalName).toBe('laporan.pdf');
    expect(metadata.fileExt).toBe('.pdf');
    expect(metadata.originalSize).toBe(PDF.length);
    expect(metadata.encryptedSize).toBe(ciphertext.length);
    expect(metadata.salt).toMatch(/^[0-9a-f]{32}$/);
    expect(metadata.iv).toMatch(/^[0-9a-f]{32}$/);
    expect(metadata.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(ciphertext.length % 16).toBe(0);
  });

  it('round-trip container mengembalikan byte dan metadata asli', async () => {
    const original = randomBytes(80 * 1024);
    const container = await encryptFileContainer({
      data: original,
      password: PASSWORD,
      originalName: 'kontrak.docx',
    });

    const restored = await decryptFileContainer({ container, password: PASSWORD });
    expect(restored.data.equals(original)).toBe(true);
    expect(restored.metadata.originalName).toBe('kontrak.docx');
    expect(restored.metadata.fileExt).toBe('.docx');
    expect(restored.metadata.originalSize).toBe(original.length);
  });

  it('salt dan IV acak membuat dua container berbeda', async () => {
    const first = await encryptFileContainer({ data: PDF, password: PASSWORD, originalName: 'a.pdf' });
    const second = await encryptFileContainer({ data: PDF, password: PASSWORD, originalName: 'a.pdf' });
    expect(parseContainer(first).metadata.salt).not.toBe(parseContainer(second).metadata.salt);
    expect(first.equals(second)).toBe(false);
  });

  it('kunci salah ditolak dengan pesan yang ditetapkan', async () => {
    const container = await encryptFileContainer({ data: PDF, password: PASSWORD, originalName: 'a.pdf' });
    await expect(
      decryptFileContainer({ container, password: 'kunci-yang-salah' }),
    ).rejects.toMatchObject({ message: MESSAGES.WRONG_KEY });
  });

  it('ciphertext yang diubah ditolak tanpa crash', async () => {
    const container = await encryptFileContainer({ data: PDF, password: PASSWORD, originalName: 'a.pdf' });
    const tampered = Buffer.from(container);
    tampered[tampered.length - 1] ^= 0xff;
    await expect(
      decryptFileContainer({ container: tampered, password: PASSWORD }),
    ).rejects.toBeInstanceOf(Error);
  });

  it('magic header rusak ditolak sebagai container tidak valid', () => {
    const broken = Buffer.alloc(20);
    broken.write('BUKANENC', 0, 'ascii');
    expect(() => parseContainer(broken)).toThrow(ContainerError);
  });

  it('metadata yang bukan JSON valid ditolak', async () => {
    const container = await encryptFileContainer({ data: PDF, password: PASSWORD, originalName: 'a.pdf' });
    const broken = Buffer.from(container);
    broken[9] = 0x00;
    broken[10] = 0x00;
    broken[11] = 0x00;
    broken[12] = 0x02;
    expect(() => parseContainer(broken)).toThrow(ContainerError);
  });

  it('metadata dengan ukuran asli melebihi 5 MB ditolak', () => {
    const meta = {
      format: 'arsip-digital',
      version: 1,
      originalName: 'a.pdf',
      fileExt: '.pdf',
      originalSize: MAX_ORIGINAL_SIZE + 1,
      encryptedSize: 16,
      salt: '0'.repeat(32),
      iv: '0'.repeat(32),
      sha256: '0'.repeat(64),
    };
    expect(() => parseContainer(containerFrom(meta, Buffer.alloc(16)))).toThrow(ContainerError);
  });

  it('metadata dengan salt yang diubah membuat dekripsi gagal', async () => {
    const container = await encryptFileContainer({ data: PDF, password: PASSWORD, originalName: 'a.pdf' });
    const { metadata, ciphertext } = parseContainer(container);
    const tampered = containerFrom(
      { ...metadata, salt: metadata.salt.replace(/^./, (char) => (char === 'a' ? 'b' : 'a')) },
      ciphertext,
    );
    await expect(
      decryptFileContainer({ container: tampered, password: PASSWORD }),
    ).rejects.toMatchObject({ message: MESSAGES.WRONG_KEY });
  });

  it('nama berkas berbahaya dibersihkan dan ekstensi tidak didukung ditolak', async () => {
    const safe = await encryptFileContainer({
      data: PDF,
      password: PASSWORD,
      originalName: '../../etc/laporan.pdf',
    });
    expect(parseContainer(safe).metadata.originalName).toBe('laporan.pdf');

    await expect(
      encryptFileContainer({ data: PDF, password: PASSWORD, originalName: 'skrip.exe' }),
    ).rejects.toMatchObject({ message: 'Jenis atau ukuran berkas tidak didukung' });
  });

  it('berkas lebih dari 5 MB ditolak oleh lapisan layanan', async () => {
    const tooLarge = Buffer.alloc(MAX_ORIGINAL_SIZE + 1);
    await expect(
      encryptFileContainer({ data: tooLarge, password: PASSWORD, originalName: 'besar.pdf' }),
    ).rejects.toMatchObject({ message: 'Jenis atau ukuran berkas tidak didukung' });
  });
});
