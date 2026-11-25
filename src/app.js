import express from 'express';
import { createSessionMiddleware } from './config/session.js';
import { attachUser, requireAdmin, requireAuth } from './middleware/auth.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import archivesRouter from './routes/archives.js';
import authRouter from './routes/auth.js';
import dashboardRouter from './routes/dashboard.js';
import logsRouter from './routes/logs.js';
import simulasiRouter from './routes/simulasi.js';
import usersRouter from './routes/users.js';

export function createApp(options = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
  });
  app.use(express.json({ limit: '100kb' }));
  app.use(createSessionMiddleware({ store: options.sessionStore }));
  app.use(attachUser);

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok' });
  });
  app.use('/api/auth', authRouter);
  app.use('/api/archives', archivesRouter);
  app.use('/api/dashboard', dashboardRouter);
  app.use('/api/logs', logsRouter);
  app.use('/api/simulasi', requireAuth, simulasiRouter);
  app.use('/api/users', requireAuth, requireAdmin, usersRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

export const app = createApp();
