import { Router } from 'express';
import { createUser, listUsers, updateUser } from '../services/users.js';

const router = Router();
const ROLES = new Set(['admin', 'pegawai']);
const PATCH_FIELDS = new Set(['username', 'password', 'role', 'is_active']);

function badRequest(res, message) {
  res.status(400).json({ message });
}

function validateCreate(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'Payload tidak valid';
  const { username, password, role } = body;
  if (typeof username !== 'string' || !username.trim()) return 'Username wajib diisi';
  if (typeof password !== 'string' || password.length < 8) return 'Password minimal 8 karakter';
  if (!ROLES.has(role)) return 'Role tidak valid';
  return null;
}

function validatePatch(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'Payload tidak valid';
  const keys = Object.keys(body);
  if (keys.length === 0) return 'Tidak ada field yang diperbarui';
  for (const key of keys) {
    if (!PATCH_FIELDS.has(key)) return `Field tidak valid: ${key}`;
  }
  if (Object.hasOwn(body, 'username') && (typeof body.username !== 'string' || !body.username.trim())) {
    return 'Username wajib diisi';
  }
  if (Object.hasOwn(body, 'password') && (typeof body.password !== 'string' || body.password.length < 8)) {
    return 'Password minimal 8 karakter';
  }
  if (Object.hasOwn(body, 'role') && !ROLES.has(body.role)) return 'Role tidak valid';
  if (Object.hasOwn(body, 'is_active') && typeof body.is_active !== 'boolean') return 'is_active harus boolean';
  return null;
}

router.get('/', async (req, res, next) => {
  try {
    const users = await listUsers();
    res.json({ users });
  } catch (error) {
    next(error);
  }
});

router.post('/', async (req, res, next) => {
  const message = validateCreate(req.body);
  if (message) {
    badRequest(res, message);
    return;
  }
  try {
    const user = await createUser({
      username: req.body.username.trim(),
      password: req.body.password,
      role: req.body.role,
    });
    res.status(201).json({ user });
  } catch (error) {
    next(error);
  }
});

router.patch('/:id', async (req, res, next) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) {
    badRequest(res, 'ID tidak valid');
    return;
  }
  const message = validatePatch(req.body);
  if (message) {
    badRequest(res, message);
    return;
  }
  try {
    const user = await updateUser(id, req.body);
    res.json({ user });
  } catch (error) {
    next(error);
  }
});

export default router;
