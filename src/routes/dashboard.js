import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getDashboard } from '../services/dashboard.js';

const router = Router();

router.use(requireAuth);

router.get('/', async (req, res, next) => {
  try {
    const dashboard = await getDashboard({ user: req.user });
    res.json(dashboard);
  } catch (error) {
    next(error);
  }
});

export default router;
