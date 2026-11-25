import { getPool } from '../config/db.js';

function serviceError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function assertDashboardUser(user) {
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

export async function getDashboard({ user } = {}, pool = getPool()) {
  const validUser = assertDashboardUser(user);
  const scoped = validUser.role === 'pegawai';
  const archiveWhere = scoped ? 'WHERE user_id = ?' : '';
  const archiveParams = scoped ? [validUser.id] : [];

  const [countRows] = await pool.query(
    `SELECT COUNT(*) AS count FROM archives ${archiveWhere}`,
    archiveParams,
  );
  const archiveCount = Number(countRows[0]?.count ?? 0);

  const activityWhere = scoped ? 'WHERE al.user_id = ?' : '';
  const activityParams = scoped ? [validUser.id] : [];
  const [recentActivities] = await pool.query(
    `SELECT al.id, al.user_id, u.username, al.archive_id, a.original_name,
            al.activity, al.result, al.created_at
     FROM activity_logs al
     JOIN users u ON u.id = al.user_id
     LEFT JOIN archives a ON a.id = al.archive_id
     ${activityWhere}
     ORDER BY al.created_at DESC, al.id DESC
     LIMIT 5`,
    activityParams,
  );

  return { archiveCount, recentActivities };
}
