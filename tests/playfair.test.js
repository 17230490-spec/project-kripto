import { describe, expect, it } from 'vitest';
import {
  buildSquare,
  playfairDecrypt,
  playfairDecryptTrace,
  playfairEncrypt,
  playfairEncryptTrace,
  stripFillerX,
} from '../src/services/playfair.js';
import {
  decodeLettersToBytes,
  encodeBytesToLetters,
} from '../src/services/binaryLetterCodec.js';

const encryptText = (text, keyword) =>
  playfairEncrypt(Buffer.from(text, 'ascii'), keyword).toString('ascii');
const decryptText = (text, keyword) =>
  playfairDecrypt(Buffer.from(text, 'ascii'), keyword).toString('ascii');

describe('Playfair 5x5', () => {
  it('vektor 7.7: BALLOON dengan MONARCHY menjadi IBSUPMNA', () => {
    expect(encryptText('BALLOON', 'MONARCHY')).toBe('IBSUPMNA');
  });

  it('vektor 7.7: IBSUPMNA dengan MONARCHY menjadi BALXLOON, lalu BALLOON setelah X dibuang', () => {
    expect(decryptText('IBSUPMNA', 'MONARCHY')).toBe('BALXLOON');
    expect(stripFillerX(Buffer.from('BALXLOON', 'ascii')).toString('ascii')).toBe('BALLOON');
  });

  it('vektor 7.7: Playfair pada hasil codec CFFAEEEG menjadi HEIOIUIUFI', () => {
    expect(encryptText('CFFAEEEG', 'MONARCHY')).toBe('HEIOIUIUFI');
  });

  it('matriks MONARCHY terisi sesuai aturan tanpa huruf berulang', () => {
    const { matrix } = buildSquare('MONARCHY');
    expect(matrix).toEqual([
      ['M', 'O', 'N', 'A', 'R'],
      ['C', 'H', 'Y', 'B', 'D'],
      ['E', 'F', 'G', 'I', 'K'],
      ['L', 'P', 'Q', 'S', 'T'],
      ['U', 'V', 'W', 'X', 'Z'],
    ]);
  });

  it('round-trip Playfair untuk seluruh 256 nilai byte dan beberapa kata kunci', () => {
    const allBytes = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    const letters = encodeBytesToLetters(allBytes);
    for (const keyword of ['MONARCHY', 'KUNCI RAHASIA', 'JJJJ', 'ABCDEFGHIJKLMNOP']) {
      const encrypted = playfairEncrypt(letters, keyword);
      const decrypted = stripFillerX(playfairDecrypt(encrypted, keyword));
      expect([...decodeLettersToBytes(decrypted)]).toEqual([...allBytes]);
    }
  });

  it('menolak ciphertext dengan byte di luar 25 huruf Playfair tanpa crash', () => {
    expect(() => playfairDecrypt(Buffer.from([0x00, 0x41]), 'MONARCHY')).toThrow();
    expect(() => playfairDecrypt(Buffer.from('J@', 'ascii'), 'MONARCHY')).toThrow();
    expect(() => playfairDecrypt(Buffer.from('ABC', 'ascii'), 'MONARCHY')).toThrow();
  });

  it('mode trace mencatat matriks, sisipan X, aturan, dan hasil per pasangan', () => {
    const { output, trace } = playfairEncryptTrace('CFFAEEEG', 'MONARCHY');
    expect(output).toBe('HEIOIUIUFI');
    expect(trace.square.matrix).toEqual(buildSquare('MONARCHY').matrix);
    expect(trace.pairs.map((p) => p.input)).toEqual(['CF', 'FA', 'EX', 'EX', 'EG']);
    expect(trace.pairs.map((p) => p.output)).toEqual(['HE', 'IO', 'IU', 'IU', 'FI']);
    expect(trace.pairs.map((p) => p.rule)).toEqual([
      'persegi panjang',
      'persegi panjang',
      'persegi panjang',
      'persegi panjang',
      'baris sama',
    ]);
    expect(trace.padding.isOdd).toBe(false);
    expect(trace.padding.inserted).toBe(2);

    const decrypted = playfairDecryptTrace('HEIOIUIUFI', 'MONARCHY');
    expect(decrypted.output).toBe('CFFAEXEXEG');
    expect(decrypted.trace.stripped).toBe('CFFAEEEG');
  });
});
