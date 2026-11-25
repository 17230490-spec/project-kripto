import path from 'node:path';

export const MAX_ORIGINAL_SIZE = 5 * 1024 * 1024;
export const MAX_CONTAINER_SIZE = 12 * 1024 * 1024;

export const ALLOWED_EXTENSIONS = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'];
export const ALLOWED_EXTENSION_SET = new Set(ALLOWED_EXTENSIONS);

export const MIME_BY_EXTENSION = {
  '.pdf': 'application/pdf',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

export function extensionOf(fileName) {
  return path.extname(String(fileName ?? '')).toLowerCase();
}

export function isAllowedArchive(fileName) {
  return ALLOWED_EXTENSION_SET.has(extensionOf(fileName));
}

export function sanitizeOriginalName(fileName) {
  const base = path.basename(String(fileName ?? ''));
  const cleaned = base.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 180);
  return cleaned || 'arsip';
}

export function mimeForExtension(extension) {
  return MIME_BY_EXTENSION[extension] ?? 'application/octet-stream';
}
