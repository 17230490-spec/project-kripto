import { Router } from 'express';
import { env } from '../config/env.js';
import { requireAuth } from '../middleware/auth.js';
import { logActivity } from '../services/activityLogs.js';
import { findByUsername, toPublicUser, verifyPassword } from '../services/users.js';

const router = Router();
const LOGIN_FAILURE_MESSAGE = 'Nama pengguna atau kata sandi salah';

router.post('/login', async (req, res, next) => {
  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!username || !password) {
    res.status(401).json({ message: LOGIN_FAILURE_MESSAGE });
    return;
  }

  try {
    const user = await findByUsername(username);
    const valid = user ? await verifyPassword(password, user.password_hash) : false;
    if (!user || !valid || !user.is_active) {
      if (user) {
        try {
          await logActivity({ userId: user.id, activity: 'LOGIN', result: 'FAILURE' });
        } catch {
          // best effort
        }
      }
      res.status(401).json({ message: LOGIN_FAILURE_MESSAGE });
      return;
    }

    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => (err ? reject(err) : resolve()));
    });
    req.session.userId = user.id;
    await new Promise((resolve, reject) => {
      req.session.save((err) => (err ? reject(err) : resolve()));
    });
    await logActivity({ userId: user.id, activity: 'LOGIN', result: 'SUCCESS' });
    res.json({ user: toPublicUser(user) });
  } catch (error) {
    next(error);
  }
});

router.post('/logout', requireAuth, async (req, res, next) => {
  const userId = req.user.id;
  try {
    await logActivity({ userId, activity: 'LOGOUT', result: 'SUCCESS' });
    req.session.destroy((error) => {
      if (error) {
        next(error);
        return;
      }
      res.clearCookie('connect.sid', {
        httpOnly: true,
        sameSite: env.COOKIE_SAME_SITE,
        secure: env.COOKIE_SECURE,
        path: '/',
      });
      res.json({ message: 'Logout berhasil' });
    });
  } catch (error) {
    next(error);
  }
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

export default router;
