import { findById, toPublicUser } from '../services/users.js';

function send401(res) {
  res.status(401).json({ message: 'Autentikasi diperlukan' });
}

export function requireAuth(req, res, next) {
  if (!req.user) {
    send401(res);
    return;
  }
  next();
}

export function requireAdmin(req, res, next) {
  if (!req.user) {
    send401(res);
    return;
  }
  if (req.user.role !== 'admin') {
    res.status(403).json({ message: 'Akses ditolak' });
    return;
  }
  next();
}

export function requireOwnerOrAdmin(getOwnerId) {
  return async (req, res, next) => {
    if (!req.user) {
      send401(res);
      return;
    }
    if (req.user.role === 'admin') {
      next();
      return;
    }
    try {
      const ownerId = await getOwnerId(req);
      if (ownerId !== req.user.id) {
        res.status(403).json({ message: 'Akses ditolak' });
        return;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

export async function attachUser(req, res, next) {
  const userId = req.session?.userId;
  if (!userId) {
    req.user = null;
    next();
    return;
  }
  try {
    const user = await findById(userId);
    if (!user || !user.is_active) {
      req.session.userId = null;
      req.user = null;
      next();
      return;
    }
    req.user = toPublicUser(user);
    next();
  } catch (error) {
    next(error);
  }
}
