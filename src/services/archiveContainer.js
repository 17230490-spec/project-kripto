import { ArchiveCryptoError, MESSAGES, decryptArchive, encryptArchive } from './archiveCrypto.js';
import {
  ALLOWED_EXTENSION_SET,
  MAX_ORIGINAL_SIZE,
  extensionOf,
  isAllowedArchive,
  sanitizeOriginalName,
} from './fileTypes.js';

export const CONTAINER_MAGIC = 'ARSIPENC';
export const CONTAINER_VERSION = 1;
export const HEADER_LENGTH = 13;
export const MAX_METADATA_LENGTH = 4096;

const INVALID_CONTAINER_MESSAGE = MESSAGES.WRONG_KEY;
const INVALID_FILE_MESSAGE = 'Jenis atau ukuran berkas tidak didukung';

export class ContainerError extends Error {
  constructor(code, message, statusCode = 400) {
    super(message);
    this.name = 'ContainerError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

function invalidContainer() {
  return new ContainerError('INVALID_CONTAINER', INVALID_CONTAINER_MESSAGE);
}

function assertHex(value, length, label) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${length}}$`).test(value)) {
    throw invalidContainer();
  }
}

export async function encryptFileContainer({ data, password, originalName }) {
  const original = Buffer.isBuffer(data) ? data : Buffer.from(data ?? []);
  if (original.length > MAX_ORIGINAL_SIZE) {
    throw new ContainerError('TOO_LARGE', INVALID_FILE_MESSAGE, 413);
  }

  const safeName = sanitizeOriginalName(originalName);
  const fileExt = extensionOf(safeName);
  if (!isAllowedArchive(safeName)) {
    throw new ContainerError('INVALID_TYPE', INVALID_FILE_MESSAGE, 400);
  }

  const encrypted = await encryptArchive({ data: original, password });
  const metadata = {
    format: 'arsip-digital',
    version: CONTAINER_VERSION,
    originalName: safeName,
    fileExt,
    originalSize: original.length,
    encryptedSize: encrypted.encrypted.length,
    sha256: encrypted.sha256,
    salt: encrypted.salt,
    iv: encrypted.iv,
    createdAt: new Date().toISOString(),
  };

  const metadataBuffer = Buffer.from(JSON.stringify(metadata), 'utf8');
  const header = Buffer.alloc(HEADER_LENGTH);
  header.write(CONTAINER_MAGIC, 0, 'ascii');
  header[8] = CONTAINER_VERSION;
  header.writeUInt32BE(metadataBuffer.length, 9);

  return Buffer.concat([header, metadataBuffer, encrypted.encrypted]);
}

export function parseContainer(container) {
  const buffer = Buffer.isBuffer(container) ? container : Buffer.from(container ?? []);
  if (buffer.length < HEADER_LENGTH) {
    throw invalidContainer();
  }
  if (buffer.subarray(0, 8).toString('ascii') !== CONTAINER_MAGIC) {
    throw invalidContainer();
  }
  if (buffer[8] !== CONTAINER_VERSION) {
    throw invalidContainer();
  }

  const metadataLength = buffer.readUInt32BE(9);
  if (metadataLength === 0 || metadataLength > MAX_METADATA_LENGTH) {
    throw invalidContainer();
  }
  if (HEADER_LENGTH + metadataLength > buffer.length) {
    throw invalidContainer();
  }

  let metadata;
  try {
    metadata = JSON.parse(buffer.subarray(HEADER_LENGTH, HEADER_LENGTH + metadataLength).toString('utf8'));
  } catch {
    throw invalidContainer();
  }

  const ciphertext = buffer.subarray(HEADER_LENGTH + metadataLength);
  if (
    !metadata ||
    metadata.format !== 'arsip-digital' ||
    metadata.version !== CONTAINER_VERSION ||
    typeof metadata.originalName !== 'string' ||
    metadata.originalName.length === 0 ||
    metadata.originalName.length > 255 ||
    typeof metadata.fileExt !== 'string' ||
    !ALLOWED_EXTENSION_SET.has(metadata.fileExt) ||
    extensionOf(metadata.originalName) !== metadata.fileExt ||
    !Number.isInteger(metadata.originalSize) ||
    metadata.originalSize < 0 ||
    metadata.originalSize > MAX_ORIGINAL_SIZE ||
    !Number.isInteger(metadata.encryptedSize) ||
    metadata.encryptedSize !== ciphertext.length ||
    ciphertext.length % 16 !== 0
  ) {
    throw invalidContainer();
  }

  assertHex(metadata.sha256, 64, 'sha256');
  assertHex(metadata.salt, 32, 'salt');
  assertHex(metadata.iv, 32, 'iv');

  return { metadata, ciphertext };
}

export async function decryptFileContainer({ container, password }) {
  const { metadata, ciphertext } = parseContainer(container);
  const data = await decryptArchive({
    encrypted: ciphertext,
    salt: metadata.salt,
    iv: metadata.iv,
    sha256: metadata.sha256,
    password,
  });

  if (data.length !== metadata.originalSize) {
    throw new ArchiveCryptoError('INTEGRITY', MESSAGES.INTEGRITY);
  }

  return { data, metadata };
}
