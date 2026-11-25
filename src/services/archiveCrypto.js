import {
  createCipheriv,
  createDecipheriv,
  createHash,
  pbkdf2,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import {
  decodeLettersToBytes,
  encodeBytesToLetters,
} from './binaryLetterCodec.js';
import {
  playfairDecrypt,
  playfairEncrypt,
  stripFillerX,
} from './playfair.js';

export const PBKDF2_ITERATIONS = 100000;
export const PBKDF2_KEY_LENGTH = 32;
export const AES_KEY_LENGTH = 16;
export const SALT_LENGTH = 16;
export const IV_LENGTH = 16;

export const MESSAGES = {
  WRONG_KEY: 'Kunci salah atau berkas rusak',
  INTEGRITY: 'Arsip tidak utuh',
};

export class ArchiveCryptoError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ArchiveCryptoError';
    this.code = code;
  }
}

function wrongKeyError() {
  return new ArchiveCryptoError('WRONG_KEY', MESSAGES.WRONG_KEY);
}

function integrityError() {
  return new ArchiveCryptoError('INTEGRITY', MESSAGES.INTEGRITY);
}

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

export function deriveKeys(password, salt) {
  const passwordValue = String(password ?? '');
  const saltBuffer = Buffer.isBuffer(salt) ? salt : Buffer.from(salt);
  return new Promise((resolve, reject) => {
    pbkdf2(
      passwordValue,
      saltBuffer,
      PBKDF2_ITERATIONS,
      PBKDF2_KEY_LENGTH,
      'sha256',
      (error, derived) => {
        if (error) {
          reject(error);
          return;
        }
        const aesKey = Buffer.from(derived.subarray(0, AES_KEY_LENGTH));
        let playfairKeyword = '';
        for (const byte of derived.subarray(AES_KEY_LENGTH)) {
          playfairKeyword += String.fromCharCode('A'.charCodeAt(0) + (byte % 26));
        }
        resolve({ derived, aesKey, playfairKeyword });
      },
    );
  });
}

export async function encryptArchive({ data, password }) {
  const original = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const { aesKey, playfairKeyword } = await deriveKeys(password, salt);

  const letters = encodeBytesToLetters(original);
  const stageOne = playfairEncrypt(letters, playfairKeyword);

  const cipher = createCipheriv('aes-128-cbc', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(stageOne), cipher.final()]);

  return {
    encrypted,
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    sha256: sha256Hex(original),
  };
}

export function decryptArchiveWithKeys({ encrypted, iv, aesKey, playfairKeyword, sha256 }) {
  let stageOne;
  try {
    const ivBuffer = Buffer.isBuffer(iv) ? iv : Buffer.from(iv, 'hex');
    const decipher = createDecipheriv('aes-128-cbc', aesKey, ivBuffer);
    stageOne = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch {
    throw wrongKeyError();
  }

  let plaintext;
  try {
    const decryptedLetters = playfairDecrypt(stageOne, playfairKeyword);
    const withoutFiller = stripFillerX(decryptedLetters);
    plaintext = decodeLettersToBytes(withoutFiller);
  } catch {
    throw wrongKeyError();
  }

  const expected = Buffer.from(String(sha256 ?? ''), 'hex');
  const actual = createHash('sha256').update(plaintext).digest();
  const matches = expected.length === actual.length && timingSafeEqual(actual, expected);
  if (!matches) {
    throw integrityError();
  }

  return plaintext;
}

export async function decryptArchive({ encrypted, salt, iv, sha256, password }) {
  const { aesKey, playfairKeyword } = await deriveKeys(password, Buffer.from(salt, 'hex'));
  return decryptArchiveWithKeys({
    encrypted,
    iv: Buffer.from(iv, 'hex'),
    aesKey,
    playfairKeyword,
    sha256,
  });
}
