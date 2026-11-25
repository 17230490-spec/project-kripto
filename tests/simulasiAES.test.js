import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  decryptBlock,
  encryptBlock,
  expandKey,
  simulateArchive,
} from '../src/services/simulasiAES.js';

const FIPS_KEY = '2b7e151628aed2a6abf7158809cf4f3c';
const FIPS_IV = '000102030405060708090a0b0c0d0e0f';
const key = Buffer.from(FIPS_KEY, 'hex');
const iv = Buffer.from(FIPS_IV, 'hex');

function nodeCbcEncrypt(plaintext, keyBuffer, ivBuffer) {
  const cipher = createCipheriv('aes-128-cbc', keyBuffer, ivBuffer);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

function nodeCbcDecrypt(ciphertext, keyBuffer, ivBuffer) {
  const decipher = createDecipheriv('aes-128-cbc', keyBuffer, ivBuffer);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

describe('AES edukasi FIPS-197', () => {
  it('vektor FIPS-197 Appendix B', () => {
    const plaintext = Buffer.from('3243f6a8885a308d313198a2e0370734', 'hex');
    const ciphertext = encryptBlock(plaintext, key);
    expect(ciphertext.toString('hex')).toBe('3925841d02dc09fbdc118597196a0b32');
    expect(decryptBlock(ciphertext, key).toString('hex')).toBe('3243f6a8885a308d313198a2e0370734');
  });

  it('vektor FIPS-197 Appendix C.1', () => {
    const c1Key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    const plaintext = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
    const ciphertext = encryptBlock(plaintext, c1Key);
    expect(ciphertext.toString('hex')).toBe('69c4e0d86a7b0430d8cdb78070b4c55a');
    expect(decryptBlock(ciphertext, c1Key).toString('hex')).toBe('00112233445566778899aabbccddeeff');
  });

  it('ekspansi kunci menghasilkan 11 round key dan round key 1 sesuai FIPS-197', () => {
    const roundKeys = expandKey(key);
    expect(roundKeys).toHaveLength(11);
    expect(roundKeys[0].toString('hex')).toBe(FIPS_KEY);
    expect(roundKeys[1].toString('hex')).toBe('a0fafe1788542cb123a339392a6c7605');
  });

  it('AES-128-CBC edukasi cocok dengan node:crypto untuk berbagai panjang masukan', () => {
    const samples = [
      Buffer.alloc(0),
      Buffer.from('A'),
      randomBytes(15),
      randomBytes(16),
      randomBytes(17),
      randomBytes(1000),
    ];
    for (const plaintext of samples) {
      const expected = nodeCbcEncrypt(plaintext, key, iv);
      const actual = aesCbcEncrypt(plaintext, key, iv);
      expect(actual.toString('hex')).toBe(expected.toString('hex'));
      expect(nodeCbcDecrypt(actual, key, iv).equals(plaintext)).toBe(true);
    }
  });

  it('dekripsi CBC edukasi membalik enkripsi node:crypto dan menolak padding rusak', () => {
    const plaintext = randomBytes(321);
    const ciphertext = nodeCbcEncrypt(plaintext, key, iv);
    expect(aesCbcDecrypt(ciphertext, key, iv).equals(plaintext)).toBe(true);

    const corrupted = Buffer.from(ciphertext);
    corrupted[corrupted.length - 1] ^= 0xff;
    expect(() => aesCbcDecrypt(corrupted, key, iv)).toThrow(/padding/i);
  });

  it('simulasi %PDF + MONARCHY menampilkan seluruh langkah dan status Cocok', () => {
    const result = simulateArchive({
      text: '%PDF',
      playfairKeyword: 'MONARCHY',
      aesKeyHex: FIPS_KEY,
      ivHex: FIPS_IV,
    });

    expect(result.steps.textToBytes.hex).toBe('25504446');
    expect(result.steps.textToBytes.bytes.map((b) => b.hex)).toEqual(['25', '50', '44', '46']);
    expect(result.steps.byteToLetters.letters).toBe('CFFAEEEG');
    expect(result.steps.playfairSquare.matrix).toEqual([
      ['M', 'O', 'N', 'A', 'R'],
      ['C', 'H', 'Y', 'B', 'D'],
      ['E', 'F', 'G', 'I', 'K'],
      ['L', 'P', 'Q', 'S', 'T'],
      ['U', 'V', 'W', 'X', 'Z'],
    ]);
    expect(result.steps.playfairPairs.pairs.map((p) => p.input)).toEqual(['CF', 'FA', 'EX', 'EX', 'EG']);
    expect(result.steps.playfairPairs.padding).toMatchObject({ isOdd: false, inserted: 2 });
    expect(result.steps.playfairEncrypt.pairs.map((p) => p.output)).toEqual(['HE', 'IO', 'IU', 'IU', 'FI']);
    expect(result.steps.playfairEncrypt.output).toBe('HEIOIUIUFI');
    expect(result.steps.aesInput.asciiHex).toBe('4845494f495549554649');
    expect(result.steps.aesInput.paddingLength).toBe(6);
    expect(result.steps.aesInput.paddedHex).toBe('4845494f495549554649060606060606');
    expect(result.steps.aes.roundKeys).toHaveLength(11);
    expect(result.steps.aes.blocks).toHaveLength(1);
    expect(result.steps.aes.blocks[0].index).toBe(1);
    expect(result.steps.aes.blocks[0].xorWithPrev.prevHex).toBe(FIPS_IV);
    expect(result.steps.aes.blocks[0].round1.subBytes).toBeTruthy();
    expect(result.steps.aes.blocks[0].round1.shiftRows).toBeTruthy();
    expect(result.steps.aes.blocks[0].round1.mixColumns).toBeTruthy();
    expect(result.steps.aes.blocks[0].round1.addRoundKey).toBeTruthy();
    expect(result.steps.aes.blocks[0].round10.mixColumns).toBeUndefined();
    expect(result.ciphertextHex).toHaveLength(32);
    expect(result.steps.decryption.text).toBe('%PDF');
    expect(result.steps.decryption.playfair.stripped).toBe('CFFAEEEG');
    expect(result.steps.matching.status).toBe('Cocok');
    expect(result.steps.matching.checks.every((check) => check.cocok)).toBe(true);
  });

  it('simulasi dengan masukan yang menghasilkan dua blok AES tetap cocok', () => {
    const result = simulateArchive({
      text: 'ABCDEFGH',
      playfairKeyword: 'KUNCI',
      aesKeyHex: '000102030405060708090a0b0c0d0e0f',
      ivHex: '101112131415161718191a1b1c1d1e1f',
    });
    expect(result.steps.aes.blocks.length).toBeGreaterThanOrEqual(2);
    expect(result.steps.aes.blocks[1].xorWithPrev.prevHex).toBe(result.steps.aes.blocks[0].ciphertextHex);
    expect(result.steps.matching.status).toBe('Cocok');
    expect(result.steps.decryption.text).toBe('ABCDEFGH');
  });
});
