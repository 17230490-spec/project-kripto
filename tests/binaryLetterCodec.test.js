import { describe, expect, it } from 'vitest';
import {
  decodeLettersToBytes,
  encodeBytesToLetters,
  isCodecLetter,
} from '../src/services/binaryLetterCodec.js';

describe('binaryLetterCodec', () => {
  it('mengubah byte 25 50 44 46 menjadi CFFAEEEG (vektor 7.7)', () => {
    const input = Buffer.from([0x25, 0x50, 0x44, 0x46]);
    expect(encodeBytesToLetters(input).toString('ascii')).toBe('CFFAEEEG');
  });

  it('mengubah CFFAEEEG kembali menjadi byte 25 50 44 46 (vektor 7.7)', () => {
    const decoded = decodeLettersToBytes(Buffer.from('CFFAEEEG', 'ascii'));
    expect([...decoded]).toEqual([0x25, 0x50, 0x44, 0x46]);
  });

  it('round-trip untuk seluruh 256 nilai byte', () => {
    const allBytes = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    const letters = encodeBytesToLetters(allBytes);
    expect(letters.length).toBe(512);
    expect([...decodeLettersToBytes(letters)]).toEqual([...allBytes]);
  });

  it('menolak huruf di luar tabel nibble (J dan X tidak dipakai)', () => {
    expect(() => decodeLettersToBytes(Buffer.from('CJ', 'ascii'))).toThrow();
    expect(() => decodeLettersToBytes(Buffer.from('CX', 'ascii'))).toThrow();
    expect(() => decodeLettersToBytes(Buffer.from('CFF', 'ascii'))).toThrow();
    expect(isCodecLetter('J'.charCodeAt(0))).toBe(false);
    expect(isCodecLetter('X'.charCodeAt(0))).toBe(false);
    expect(isCodecLetter('Q'.charCodeAt(0))).toBe(true);
  });
});
