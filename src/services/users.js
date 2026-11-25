import bcrypt from 'bcrypt';
import { getPool } from '../config/db.js';

const BCRYPT_COST = 12;
const ROLES = new Set(['admin', 'pegawai']);
const PUBLIC_FIELDS = 'id, username, role, is_active, created_at, updated_at';

export function toPublicUser(user) {
  if (!user) return null;
  const { password_hash, ...publicUser } = user;
  return publicUser;
}

export async function findByUsername(username, pool = getPool()) {
  const [rows] = await pool.query('SELECT * FROM users WHERE username = ? LIMIT 1', [username]);
  return rows[0] ?? null;
}

export async function findById(id, pool = getPool()) {
  const [rows] = await pool.query('SELECT * FROM users WHERE id = ? LIMIT 1', [id]);
  return rows[0] ?? null;
}

export async function verifyPassword(password, passwordHash) {
  return bcrypt.compare(password, passwordHash);
}

function validationError(message) {
  const error = new Error(message);
  error.statusCode = 400;
  return error;
}

function normalizeUsername(value) {
  if (typeof value !== 'string') throw validationError('Username wajib diisi');
  const username = value.trim();
  if (!username) throw validationError('Username wajib diisi');
  return username;
}

function validatePassword(value) {
  if (typeof value !== 'string' || value.length < 8) {
    throw validationError('Password minimal 8 karakter');
  }
  return value;
}

function validateRole(value) {
  if (!ROLES.has(value)) throw validationError('Role tidak valid');
  return value;
}

function validateIsActive(value) {
  if (typeof value !== 'boolean') throw validationError('is_active harus boolean');
  return value;
}

function isDuplicateUsername(error) {
  return error?.code === 'ER_DUP_ENTRY';
}

export async function listUsers(pool = getPool()) {
  const [rows] = await pool.query(
    `SELECT ${PUBLIC_FIELDS} FROM users ORDER BY id ASC`,
  );
  return rows;
}

export async function createUser({ username, password, role }, pool = getPool()) {
  const normalizedUsername = normalizeUsername(username);
  const validPassword = validatePassword(password);
  const validRole = validateRole(role);
  const passwordHash = await bcrypt.hash(validPassword, BCRYPT_COST);

  try {
    const [result] = await pool.query(
      'INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, 1)',
      [normalizedUsername, passwordHash, validRole],
    );
    const [rows] = await pool.query(
      `SELECT ${PUBLIC_FIELDS} FROM users WHERE id = ? LIMIT 1`,
      [result.insertId],
    );
    return rows[0];
  } catch (error) {
    if (isDuplicateUsername(error)) {
      const dup = new Error('Username sudah digunakan');
      dup.statusCode = 409;
      throw dup;
    }
    throw error;
  }
}

const PATCH_FIELDS = new Set(['username', 'password', 'role', 'is_active']);

export async function updateUser(id, patch, pool = getPool()) {
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
    throw validationError('Payload tidak valid');
  }
  const keys = Object.keys(patch);
  if (keys.length === 0) throw validationError('Tidak ada field yang diperbarui');
  for (const key of keys) {
    if (!PATCH_FIELDS.has(key)) throw validationError(`Field tidak valid: ${key}`);
  }

  const updates = [];
  const values = [];

  if (Object.hasOwn(patch, 'username')) {
    updates.push('username = ?');
    values.push(normalizeUsername(patch.username));
  }
  if (Object.hasOwn(patch, 'password')) {
    updates.push('password_hash = ?');
    values.push(await bcrypt.hash(validatePassword(patch.password), BCRYPT_COST));
  }
  if (Object.hasOwn(patch, 'role')) {
    updates.push('role = ?');
    values.push(validateRole(patch.role));
  }
  if (Object.hasOwn(patch, 'is_active')) {
    updates.push('is_active = ?');
    values.push(validateIsActive(patch.is_active) ? 1 : 0);
  }

  try {
    const [result] = await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
      [...values, id],
    );
    if (result.affectedRows === 0) {
      const notFound = new Error('Pengguna tidak ditemukan');
      notFound.statusCode = 404;
      throw notFound;
    }
  } catch (error) {
    if (isDuplicateUsername(error)) {
      const dup = new Error('Username sudah digunakan');
      dup.statusCode = 409;
      throw dup;
    }
    throw error;
  }

  const [rows] = await pool.query(
    `SELECT ${PUBLIC_FIELDS} FROM users WHERE id = ? LIMIT 1`,
    [id],
  );
  return rows[0];
}
