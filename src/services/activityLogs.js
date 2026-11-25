import { getPool } from '../config/db.js';

function serviceError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

export async function logActivity({ userId, archiveId = null, activity, result }, pool = getPool()) {
  await pool.query(
    'INSERT INTO activity_logs (user_id, archive_id, activity, result) VALUES (?, ?, ?, ?)',
    [userId, archiveId ?? null, activity, result],
  );
}

export async function listActivityLogs({ tanggal, userId } = {}, pool = getPool()) {
  const conditions = [];
  const params = [];

  if (typeof tanggal === 'string' && tanggal.trim()) {
    conditions.push('DATE(al.created_at) = ?');
    params.push(tanggal.trim());
  }

  if (userId !== undefined) {
    const parsed = Number(userId);
    if (!Number.isInteger(parsed) || parsed <= 0) {
      throw serviceError('userId tidak valid', 400);
    }
    conditions.push('al.user_id = ?');
    params.push(parsed);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const [rows] = await pool.query(
    `SELECT al.id, al.user_id, u.username, al.archive_id, a.original_name,
            al.activity, al.result, al.created_at
     FROM activity_logs al
     JOIN users u ON u.id = al.user_id
     LEFT JOIN archives a ON a.id = al.archive_id
     ${where}
     ORDER BY al.created_at DESC, al.id DESC`,
    params,
  );
  return rows;
}
