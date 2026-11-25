import { Router } from 'express';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { listActivityLogs } from '../services/activityLogs.js';

const router = Router();

router.use(requireAuth, requireAdmin);

router.get('/', async (req, res, next) => {
  try {
    const tanggal = typeof req.query.tanggal === 'string' ? req.query.tanggal : undefined;
    const userIdRaw = req.query.userId;
    let userId;
    if (userIdRaw !== undefined) {
      if (typeof userIdRaw !== 'string' || !/^\d+$/.test(userIdRaw)) {
        res.status(400).json({ message: 'userId tidak valid' });
        return;
      }
      userId = Number.parseInt(userIdRaw, 10);
      if (!Number.isInteger(userId) || userId <= 0) {
        res.status(400).json({ message: 'userId tidak valid' });
        return;
      }
    }

    const logs = await listActivityLogs({ tanggal, userId });
    res.json({ logs });
  } catch (error) {
    next(error);
  }
});

export default router;
