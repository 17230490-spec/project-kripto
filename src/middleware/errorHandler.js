export function notFoundHandler(req, res) {
  res.status(404).json({ message: 'Tidak ditemukan' });
}

export function errorHandler(error, req, res, next) {
  if (res.headersSent) {
    next(error);
    return;
  }
  const status = error.statusCode ?? error.status ?? 500;
  const message = status >= 500 ? 'Terjadi kesalahan pada server' : error.message;
  res.status(status).json({ message });
}
