import { Router } from 'express';
import { simulateArchive } from '../services/simulasiAES.js';

const router = Router();

router.post('/', (req, res) => {
  try {
    const result = simulateArchive(req.body ?? {});
    res.json(result);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

export default router;
