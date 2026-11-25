import { createCipheriv, createDecipheriv } from 'node:crypto';
import {
  decodeLettersToBytes,
  encodeBytesToLetters,
} from './binaryLetterCodec.js';
import {
  playfairDecryptTrace,
  playfairEncrypt,
  playfairEncryptTrace,
} from './playfair.js';

const SBOX = Uint8Array.from([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

const INV_SBOX = Uint8Array.from([
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]);

const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

function hexByte(value) {
  return value.toString(16).padStart(2, '0');
}

function bufferToHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function stateToMatrix(state) {
  const matrix = [];
  for (let row = 0; row < 4; row += 1) {
    const cells = [];
    for (let col = 0; col < 4; col += 1) {
      cells.push(hexByte(state[row + 4 * col]));
    }
    matrix.push(cells);
  }
  return matrix;
}

function toBlock(input, label) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  if (bytes.length !== 16) {
    throw new Error(`${label} harus 16 byte`);
  }
  return Uint8Array.from(bytes);
}

function validateKey(keyBytes) {
  if (keyBytes.length !== 16) {
    throw new Error('Kunci AES-128 harus 16 byte');
  }
}

export function expandKey(key) {
  const keyBytes = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  validateKey(keyBytes);
  const words = new Uint8Array(176);
  words.set(keyBytes, 0);

  for (let wordIndex = 4; wordIndex < 44; wordIndex += 1) {
    const temp = words.slice((wordIndex - 1) * 4, wordIndex * 4);
    if (wordIndex % 4 === 0) {
      const first = temp[0];
      temp[0] = SBOX[temp[1]] ^ RCON[wordIndex / 4];
      temp[1] = SBOX[temp[2]];
      temp[2] = SBOX[temp[3]];
      temp[3] = SBOX[first];
    }
    for (let i = 0; i < 4; i += 1) {
      words[wordIndex * 4 + i] = words[(wordIndex - 4) * 4 + i] ^ temp[i];
    }
  }

  const roundKeys = [];
  for (let round = 0; round <= 10; round += 1) {
    roundKeys.push(Buffer.from(words.slice(round * 16, round * 16 + 16)));
  }
  return roundKeys;
}

function addRoundKey(state, roundKey) {
  for (let i = 0; i < 16; i += 1) state[i] ^= roundKey[i];
}

function subBytes(state, inverse = false) {
  const box = inverse ? INV_SBOX : SBOX;
  for (let i = 0; i < 16; i += 1) state[i] = box[state[i]];
}

function shiftRows(state, inverse = false) {
  const copy = Uint8Array.from(state);
  for (let row = 0; row < 4; row += 1) {
    for (let col = 0; col < 4; col += 1) {
      const sourceCol = inverse ? (col - row + 4) % 4 : (col + row) % 4;
      state[row + 4 * col] = copy[row + 4 * sourceCol];
    }
  }
}

function gmul(a, b) {
  let product = 0;
  let left = a;
  let right = b;
  for (let i = 0; i < 8; i += 1) {
    if (right & 1) product ^= left;
    const highBit = left & 0x80;
    left = (left << 1) & 0xff;
    if (highBit) left ^= 0x1b;
    right >>= 1;
  }
  return product;
}

function mixColumns(state) {
  for (let col = 0; col < 4; col += 1) {
    const offset = col * 4;
    const a0 = state[offset];
    const a1 = state[offset + 1];
    const a2 = state[offset + 2];
    const a3 = state[offset + 3];
    state[offset] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
    state[offset + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
    state[offset + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
    state[offset + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
  }
}

function invMixColumns(state) {
  for (let col = 0; col < 4; col += 1) {
    const offset = col * 4;
    const a0 = state[offset];
    const a1 = state[offset + 1];
    const a2 = state[offset + 2];
    const a3 = state[offset + 3];
    state[offset] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
    state[offset + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
    state[offset + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
    state[offset + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
  }
}

function encryptState(block, roundKeys) {
  const state = Uint8Array.from(block);
  addRoundKey(state, roundKeys[0]);
  for (let round = 1; round <= 9; round += 1) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, roundKeys[round]);
  }
  subBytes(state);
  shiftRows(state);
  addRoundKey(state, roundKeys[10]);
  return Buffer.from(state);
}

function decryptState(block, roundKeys) {
  const state = Uint8Array.from(block);
  addRoundKey(state, roundKeys[10]);
  for (let round = 9; round >= 1; round -= 1) {
    shiftRows(state, true);
    subBytes(state, true);
    addRoundKey(state, roundKeys[round]);
    invMixColumns(state);
  }
  shiftRows(state, true);
  subBytes(state, true);
  addRoundKey(state, roundKeys[0]);
  return Buffer.from(state);
}

export function encryptBlock(block, key) {
  return encryptState(toBlock(block, 'Plaintext'), expandKey(key));
}

export function decryptBlock(block, key) {
  return decryptState(toBlock(block, 'Ciphertext'), expandKey(key));
}

function xorBlock(a, b) {
  const result = Buffer.allocUnsafe(16);
  for (let i = 0; i < 16; i += 1) result[i] = a[i] ^ b[i];
  return result;
}

function padPkcs7(data) {
  const paddingLength = 16 - (data.length % 16);
  const padded = Buffer.alloc(data.length + paddingLength, paddingLength);
  data.copy(padded, 0);
  return { padded, paddingLength };
}

function unpadPkcs7(data) {
  if (data.length === 0 || data.length % 16 !== 0) {
    throw new Error('Padding PKCS#7 tidak valid');
  }
  const paddingLength = data[data.length - 1];
  if (paddingLength < 1 || paddingLength > 16) {
    throw new Error('Padding PKCS#7 tidak valid');
  }
  for (let i = data.length - paddingLength; i < data.length; i += 1) {
    if (data[i] !== paddingLength) throw new Error('Padding PKCS#7 tidak valid');
  }
  return data.subarray(0, data.length - paddingLength);
}

export function aesCbcEncrypt(plaintext, key, iv) {
  const data = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext);
  const keyBytes = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  const ivBytes = Buffer.isBuffer(iv) ? iv : Buffer.from(iv, 'hex');
  validateKey(keyBytes);
  if (ivBytes.length !== 16) throw new Error('IV harus 16 byte');

  const roundKeys = expandKey(keyBytes);
  const { padded } = padPkcs7(data);
  const output = Buffer.allocUnsafe(padded.length);
  let previous = ivBytes;

  for (let offset = 0; offset < padded.length; offset += 16) {
    const block = padded.subarray(offset, offset + 16);
    const ciphertext = encryptState(xorBlock(block, previous), roundKeys);
    ciphertext.copy(output, offset);
    previous = ciphertext;
  }
  return output;
}

export function aesCbcDecrypt(ciphertext, key, iv) {
  const trace = aesCbcDecryptTrace(ciphertext, key, iv);
  return trace.plaintext;
}

export function aesCbcDecryptTrace(ciphertext, key, iv) {
  const data = Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext);
  const keyBytes = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  const ivBytes = Buffer.isBuffer(iv) ? iv : Buffer.from(iv, 'hex');
  validateKey(keyBytes);
  if (ivBytes.length !== 16) throw new Error('IV harus 16 byte');
  if (data.length === 0 || data.length % 16 !== 0) {
    throw new Error('Panjang ciphertext harus kelipatan 16 byte');
  }

  const roundKeys = expandKey(keyBytes);
  const padded = Buffer.allocUnsafe(data.length);
  const blocks = [];
  let previous = ivBytes;

  for (let offset = 0; offset < data.length; offset += 16) {
    const block = data.subarray(offset, offset + 16);
    const decryptedBlock = decryptState(block, roundKeys);
    const plaintextBlock = xorBlock(decryptedBlock, previous);
    plaintextBlock.copy(padded, offset);
    blocks.push({
      index: offset / 16 + 1,
      prevHex: bufferToHex(previous),
      decryptedHex: bufferToHex(decryptedBlock),
      plaintextHex: bufferToHex(plaintextBlock),
    });
    previous = block;
  }

  const plaintext = unpadPkcs7(padded);

  return {
    plaintext,
    paddedHex: bufferToHex(padded),
    paddingLength: padded.length - plaintext.length,
    blocks,
  };
}

export function aesCbcEncryptTrace(plaintext, key, iv) {
  const data = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext);
  const keyBytes = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  const ivBytes = Buffer.isBuffer(iv) ? iv : Buffer.from(iv, 'hex');
  validateKey(keyBytes);
  if (ivBytes.length !== 16) throw new Error('IV harus 16 byte');

  const roundKeys = expandKey(keyBytes);
  const { padded, paddingLength } = padPkcs7(data);
  const output = Buffer.allocUnsafe(padded.length);
  const blocks = [];
  let previous = ivBytes;

  for (let offset = 0; offset < padded.length; offset += 16) {
    const block = padded.subarray(offset, offset + 16);
    const xored = xorBlock(block, previous);
    const detail = offset === 0;
    const ciphertext = encryptState(xored, roundKeys);
    ciphertext.copy(output, offset);

    if (detail) {
      const traced = encryptStateTraceForDisplay(xored, roundKeys);
      blocks.push({
        index: offset / 16 + 1,
        plaintextHex: bufferToHex(block),
        xorWithPrev: { prevHex: bufferToHex(previous), xorHex: bufferToHex(xored) },
        initialState: {
          stateHex: bufferToHex(xored),
          matrix: stateToMatrix(Uint8Array.from(xored)),
        },
        addRoundKey: traced.addRoundKey0,
        round1: traced.round1,
        rounds2to9: traced.rounds2to9,
        round10: traced.round10,
        ciphertextHex: bufferToHex(ciphertext),
      });
    } else {
      blocks.push({
        index: offset / 16 + 1,
        plaintextHex: bufferToHex(block),
        xorWithPrev: { prevHex: bufferToHex(previous), xorHex: bufferToHex(xored) },
        ciphertextHex: bufferToHex(ciphertext),
      });
    }
    previous = ciphertext;
  }

  return {
    ciphertext: output,
    paddedHex: bufferToHex(padded),
    paddingLength,
    roundKeys,
    blocks,
  };
}

function encryptStateTraceForDisplay(block, roundKeys) {
  const state = Uint8Array.from(block);
  const trace = {};
  addRoundKey(state, roundKeys[0]);
  trace.addRoundKey0 = {
    round: 0,
    roundKeyHex: roundKeys[0].toString('hex'),
    stateHex: bufferToHex(state),
    matrix: stateToMatrix(state),
  };
  const middle = [];
  for (let round = 1; round <= 9; round += 1) {
    const snapshots = {};
    subBytes(state);
    if (round === 1) snapshots.subBytes = { stateHex: bufferToHex(state), matrix: stateToMatrix(state) };
    shiftRows(state);
    if (round === 1) snapshots.shiftRows = { stateHex: bufferToHex(state), matrix: stateToMatrix(state) };
    mixColumns(state);
    if (round === 1) snapshots.mixColumns = { stateHex: bufferToHex(state), matrix: stateToMatrix(state) };
    addRoundKey(state, roundKeys[round]);
    if (round === 1) {
      snapshots.addRoundKey = {
        round,
        roundKeyHex: roundKeys[round].toString('hex'),
        stateHex: bufferToHex(state),
        matrix: stateToMatrix(state),
      };
      trace.round1 = snapshots;
    }
    middle.push({ round, stateHex: bufferToHex(state), matrix: stateToMatrix(state) });
  }
  const last = {};
  subBytes(state);
  last.subBytes = { stateHex: bufferToHex(state), matrix: stateToMatrix(state) };
  shiftRows(state);
  last.shiftRows = { stateHex: bufferToHex(state), matrix: stateToMatrix(state) };
  addRoundKey(state, roundKeys[10]);
  last.addRoundKey = {
    round: 10,
    roundKeyHex: roundKeys[10].toString('hex'),
    stateHex: bufferToHex(state),
    matrix: stateToMatrix(state),
  };
  trace.rounds2to9 = middle.filter((item) => item.round >= 2);
  trace.round10 = { ...last, stateHex: bufferToHex(state), matrix: stateToMatrix(state) };
  trace.ciphertextHex = bufferToHex(state);
  return trace;
}

function validateSimulationInput({ text, playfairKeyword, aesKeyHex, ivHex }) {
  if (typeof text !== 'string' || !/^[\x20-\x7e]{1,8}$/.test(text)) {
    throw new Error('Teks harus 1-8 karakter ASCII');
  }
  if (typeof playfairKeyword !== 'string' || !/^[A-Za-z]{4,16}$/.test(playfairKeyword)) {
    throw new Error('Kata kunci Playfair harus 4-16 huruf A-Z');
  }
  if (typeof aesKeyHex !== 'string' || !/^[0-9a-fA-F]{32}$/.test(aesKeyHex)) {
    throw new Error('Kunci AES-128 harus 32 digit heksadesimal');
  }
  if (typeof ivHex !== 'string' || !/^[0-9a-fA-F]{32}$/.test(ivHex)) {
    throw new Error('IV harus 32 digit heksadesimal');
  }
}

export function simulateArchive(input) {
  validateSimulationInput(input);
  const { text, playfairKeyword } = input;
  const aesKeyHex = input.aesKeyHex.toLowerCase();
  const ivHex = input.ivHex.toLowerCase();
  const keyBytes = Buffer.from(aesKeyHex, 'hex');
  const ivBytes = Buffer.from(ivHex, 'hex');

  const bytes = Buffer.from(text, 'ascii');
  const textToBytes = {
    text,
    hex: bytes.toString('hex'),
    bytes: [...bytes].map((byte, index) => ({
      char: text[index],
      ascii: byte,
      hex: hexByte(byte),
    })),
  };

  const lettersBuffer = encodeBytesToLetters(bytes);
  const letters = lettersBuffer.toString('ascii');
  const nibbles = [...bytes].map((byte, index) => ({
    byteHex: hexByte(byte),
    high: byte >> 4,
    low: byte & 0x0f,
    highLetter: letters[index * 2],
    lowLetter: letters[index * 2 + 1],
  }));

  const byteToLetters = {
    bytesHex: bytes.toString('hex'),
    nibbles,
    letters,
  };

  const playfair = playfairEncryptTrace(letters, playfairKeyword);
  const playfairSquare = {
    keyword: playfair.trace.keyword,
    matrix: playfair.trace.square.matrix,
    fillSteps: playfair.trace.square.fillSteps,
  };
  const playfairPairs = {
    input: letters,
    normalized: playfair.trace.normalization.normalized,
    pairs: playfair.trace.pairs,
    padding: playfair.trace.padding,
  };
  const playfairEncryptStep = {
    output: playfair.output,
    pairs: playfair.trace.pairs.map((pair) => ({
      index: pair.index,
      input: pair.input,
      output: pair.output,
      inserted: pair.inserted,
      insertReason: pair.insertReason,
      rule: pair.rule,
      aPos: pair.aPos,
      bPos: pair.bPos,
      aOutPos: pair.aOutPos,
      bOutPos: pair.bOutPos,
    })),
  };

  const aesPlaintext = Buffer.from(playfair.output, 'ascii');
  const paddingLength = 16 - (aesPlaintext.length % 16);
  const padded = Buffer.alloc(aesPlaintext.length + paddingLength, paddingLength);
  aesPlaintext.copy(padded, 0);
  const aesInput = {
    text: playfair.output,
    asciiHex: aesPlaintext.toString('hex'),
    paddingLength,
    padValueHex: hexByte(paddingLength),
    paddedHex: padded.toString('hex'),
  };

  const aesTrace = aesCbcEncryptTrace(aesPlaintext, keyBytes, ivBytes);
  const roundKeysHex = aesTrace.roundKeys.map((roundKey) => roundKey.toString('hex'));
  const aesStep = {
    keyHex: aesKeyHex,
    ivHex,
    roundKeys: roundKeysHex,
    roundKeyExpansion: aesTrace.roundKeys.map((roundKey, round) => ({
      round,
      words: [0, 1, 2, 3].map((word) => roundKey.subarray(word * 4, word * 4 + 4).toString('hex')),
      hex: roundKey.toString('hex'),
    })),
    blocks: aesTrace.blocks,
  };
  const ciphertext = aesTrace.ciphertext;

  const decryptionAes = aesCbcDecryptTrace(ciphertext, keyBytes, ivBytes);
  const playfairCiphertext = decryptionAes.plaintext.toString('ascii');
  const playfairDecryption = playfairDecryptTrace(playfairCiphertext, playfairKeyword);
  const stripped = playfairDecryption.trace.stripped;
  const decryptedBytes = decodeLettersToBytes(Buffer.from(stripped, 'ascii'));
  const decryptedText = decryptedBytes.toString('ascii');
  const decryption = {
    aes: {
      ciphertextHex: ciphertext.toString('hex'),
      paddedHex: decryptionAes.paddedHex,
      paddingLength: decryptionAes.paddingLength,
      plaintextHex: decryptionAes.plaintext.toString('hex'),
      playfairCiphertext,
      blocks: decryptionAes.blocks,
    },
    playfair: {
      matrix: playfairDecryption.trace.square.matrix,
      pairs: playfairDecryption.trace.pairs,
      output: playfairDecryption.output,
      stripped,
      outputHex: decryptedBytes.toString('hex'),
    },
    bytesHex: decryptedBytes.toString('hex'),
    text: decryptedText,
  };

  const referenceCipher = createCipheriv('aes-128-cbc', keyBytes, ivBytes);
  const referenceCiphertext = Buffer.concat([
    referenceCipher.update(aesPlaintext),
    referenceCipher.final(),
  ]);
  const referenceDecipher = createDecipheriv('aes-128-cbc', keyBytes, ivBytes);
  const referencePlaintext = Buffer.concat([
    referenceDecipher.update(ciphertext),
    referenceDecipher.final(),
  ]);
  const reEncryptedPlayfair = playfairEncrypt(lettersBuffer, playfairKeyword);

  const checks = [
    {
      nama: 'Playfair simulasi sama dengan mode non-trace playfair.js',
      cocok: playfair.output === reEncryptedPlayfair.toString('ascii'),
    },
    {
      nama: 'AES edukasi sama dengan node:crypto aes-128-cbc',
      cocok: ciphertext.equals(referenceCiphertext),
    },
    {
      nama: 'node:crypto dapat mendekripsi ciphertext simulasi',
      cocok: referencePlaintext.equals(aesPlaintext),
    },
    {
      nama: 'Dekripsi balik ke teks awal',
      cocok: decryptedText === text,
    },
  ];

  return {
    input: { text, playfairKeyword, aesKeyHex, ivHex },
    steps: {
      textToBytes,
      byteToLetters,
      playfairSquare,
      playfairPairs,
      playfairEncrypt: playfairEncryptStep,
      aesInput,
      aes: aesStep,
      decryption,
      matching: {
        status: checks.every((check) => check.cocok) ? 'Cocok' : 'Tidak cocok',
        checks,
        referenceCiphertextHex: referenceCiphertext.toString('hex'),
      },
    },
    ciphertextHex: ciphertext.toString('hex'),
  };
}
