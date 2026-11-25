import session from 'express-session';
import MySQLStoreFactory from 'express-mysql-session';
import { env } from './env.js';

export function createSessionMiddleware({ store } = {}) {
  const MySQLStore = MySQLStoreFactory(session);
  const sessionStore = store ?? new MySQLStore({
    host: env.DB_HOST,
    port: env.DB_PORT,
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    database: env.DB_NAME,
    clearExpired: true,
    checkExpirationInterval: 900000,
    expiration: 86400000,
    createDatabaseTable: true,
  });

  return session({
    name: 'connect.sid',
    secret: env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: env.COOKIE_SECURE,
      maxAge: 86400000,
    },
  });
}
