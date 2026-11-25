import multer from 'multer';
import { MAX_ORIGINAL_SIZE, isAllowedArchive } from '../services/fileTypes.js';

const INVALID_FILE_MESSAGE = 'Jenis atau ukuran berkas tidak didukung';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_ORIGINAL_SIZE, files: 1 },
  fileFilter(req, file, callback) {
    if (!isAllowedArchive(file.originalname)) {
      const error = new Error(INVALID_FILE_MESSAGE);
      error.code = 'INVALID_FILE_TYPE';
      callback(error);
      return;
    }
    callback(null, true);
  },
}).single('file');

function handleUpload(middleware, req, res, next) {
  middleware(req, res, (error) => {
    if (!error) {
      next();
      return;
    }
    if (error.code === 'LIMIT_FILE_SIZE') {
      res.status(413).json({ message: INVALID_FILE_MESSAGE });
      return;
    }
    if (error.code === 'INVALID_FILE_TYPE') {
      res.status(400).json({ message: INVALID_FILE_MESSAGE });
      return;
    }
    if (error instanceof multer.MulterError) {
      res.status(400).json({ message: 'Permintaan unggahan tidak valid' });
      return;
    }
    next(error);
  });
}

export function uploadArchive(req, res, next) {
  handleUpload(upload, req, res, next);
}
