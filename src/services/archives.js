import { getPool } from '../config/db.js';

const ARCHIVE_DETAIL_SELECT = `
  SELECT a.id, a.user_id, a.original_name, a.stored_name, a.file_ext,
         a.original_size, a.encrypted_size, a.sha256, a.salt, a.iv, a.created_at,
         u.username
  FROM archives a
  JOIN users u ON u.id = a.user_id
`;

const ARCHIVE_LIST_SELECT = `
  SELECT a.id, a.user_id, a.original_name, a.file_ext,
         a.original_size, a.encrypted_size, a.created_at,
         u.username
  FROM archives a
  JOIN users u ON u.id = a.user_id
`;

function serviceError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function assertListArchivesUser(user) {
  if (!user || typeof user !== 'object' || Array.isArray(user)) {
    throw serviceError('Konteks pengguna tidak valid', 400);
  }
  const { role, id } = user;
  if (role !== 'admin' && role !== 'pegawai') {
    throw serviceError('Konteks pengguna tidak valid', 400);
  }
  if (!Number.isInteger(id) || id <= 0) {
    throw serviceError('Konteks pengguna tidak valid', 400);
  }
  return { role, id };
}

export async function createArchiveRecord(record, pool = getPool()) {
  const {
    userId,
    originalName,
    storedName,
    fileExt,
    originalSize,
    encryptedSize,
    sha256,
    salt,
    iv,
  } = record;

  const [result] = await pool.query(
    `INSERT INTO archives
      (user_id, original_name, stored_name, file_ext, original_size, encrypted_size, sha256, salt, iv)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [userId, originalName, storedName, fileExt, originalSize, encryptedSize, sha256, salt, iv],
  );
  return result.insertId;
}

export async function listArchives({ user, q, tanggal } = {}, pool = getPool()) {
  const validUser = assertListArchivesUser(user);
  const conditions = [];
  const params = [];

  if (validUser.role === 'pegawai') {
    conditions.push('a.user_id = ?');
    params.push(validUser.id);
  }

  if (typeof q === 'string' && q.trim()) {
    conditions.push('a.original_name LIKE ?');
    params.push(`%${q.trim()}%`);
  }

  if (typeof tanggal === 'string' && tanggal.trim()) {
    conditions.push('DATE(a.created_at) = ?');
    params.push(tanggal.trim());
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const [rows] = await pool.query(
    `${ARCHIVE_LIST_SELECT} ${where} ORDER BY a.created_at DESC, a.id DESC`,
    params,
  );
  return rows;
}

export async function getArchiveById(id, pool = getPool()) {
  const [rows] = await pool.query(
    `${ARCHIVE_DETAIL_SELECT} WHERE a.id = ? LIMIT 1`,
    [id],
  );
  return rows[0] ?? null;
}

export async function deleteArchiveRecord(id, pool = getPool()) {
  const [result] = await pool.query('DELETE FROM archives WHERE id = ?', [id]);
  return result.affectedRows > 0;
}
