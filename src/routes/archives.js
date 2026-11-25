import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { uploadArchive } from '../middleware/upload.js';
import { logActivity } from '../services/activityLogs.js';
import { createArchiveRecord, deleteArchiveRecord, getArchiveById, listArchives } from '../services/archives.js';
import { ArchiveCryptoError } from '../services/archiveCrypto.js';
import { ContainerError, decryptFileContainer, encryptFileContainer, parseContainer } from '../services/archiveContainer.js';
import { extensionOf, mimeForExtension, sanitizeOriginalName } from '../services/fileTypes.js';
import { deleteEncrypted, readEncrypted, saveEncrypted } from '../services/storage.js';

const router = Router();

const ENCRYPT_KEY_MESSAGE = 'Kunci minimal 8 karakter dan konfirmasi harus sama';
const DECRYPT_KEY_MESSAGE = 'Kunci minimal 8 karakter';

function attachmentHeader(fileName) {
  const safe = String(fileName).replace(/[\r\n"\\]/g, '_');
  const encoded = encodeURIComponent(String(fileName)).replace(
    /['()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
  return `attachment; filename="${safe}"; filename*=UTF-8''${encoded}`;
}

function sendCryptoError(error, res, next) {
  if (error instanceof ContainerError) {
    res.status(error.statusCode).json({ message: error.message });
    return;
  }
  if (error instanceof ArchiveCryptoError) {
    res.status(400).json({ message: error.message });
    return;
  }
  next(error);
}

function canAccessArchive(reqUser, archive) {
  return reqUser.role === 'admin' || archive.user_id === reqUser.id;
}

async function cleanupSavedEncrypted(storedName) {
  if (!storedName) return;
  try {
    await deleteEncrypted(storedName);
  } catch (cleanupError) {
    console.error('Failed to cleanup orphan encrypted archive file', {
      storedName,
      message: cleanupError?.message,
    });
  }
}

router.use(requireAuth);

router.post('/', uploadArchive, async (req, res, next) => {
  if (!req.file) {
    res.status(400).json({ message: 'Berkas wajib dipilih' });
    return;
  }

  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const passwordConfirm = typeof req.body?.passwordConfirm === 'string' ? req.body.passwordConfirm : '';
  if (password.length < 8 || password !== passwordConfirm) {
    res.status(400).json({ message: ENCRYPT_KEY_MESSAGE });
    return;
  }

  let saved;
  try {
    const container = await encryptFileContainer({
      data: req.file.buffer,
      password,
      originalName: req.file.originalname,
    });
    const { metadata } = parseContainer(container);
    saved = await saveEncrypted(container);
    const id = await createArchiveRecord({
      userId: req.user.id,
      originalName: sanitizeOriginalName(req.file.originalname),
      storedName: saved.storedName,
      fileExt: metadata.fileExt,
      originalSize: metadata.originalSize,
      encryptedSize: saved.encryptedSize,
      sha256: metadata.sha256,
      salt: metadata.salt,
      iv: metadata.iv,
    });

    try {
      await logActivity({ userId: req.user.id, archiveId: id, activity: 'ENCRYPT', result: 'SUCCESS' });
    } catch {
      // best effort
    }
    try {
      await logActivity({ userId: req.user.id, archiveId: id, activity: 'UPLOAD', result: 'SUCCESS' });
    } catch {
      // best effort
    }

    res.status(201).json({
      id,
      archive: {
        id,
        original_name: sanitizeOriginalName(req.file.originalname),
        file_ext: metadata.fileExt,
        original_size: metadata.originalSize,
        encrypted_size: saved.encryptedSize,
        created_at: new Date().toISOString(),
      },
    });
  } catch (error) {
    if (saved?.storedName) {
      await cleanupSavedEncrypted(saved.storedName);
    }
    try {
      if (error instanceof ContainerError || error instanceof ArchiveCryptoError) {
        await logActivity({ userId: req.user?.id, activity: 'ENCRYPT', result: 'FAILED' });
      }
    } catch {
      // best effort
    }
    sendCryptoError(error, res, next);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const archives = await listArchives({
      user: req.user,
      q: typeof req.query.q === 'string' ? req.query.q : undefined,
      tanggal: typeof req.query.tanggal === 'string' ? req.query.tanggal : undefined,
    });
    res.json({ archives });
  } catch (error) {
    next(error);
  }
});

router.post('/:id/download', async (req, res, next) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ message: 'ID arsip tidak valid' });
    return;
  }

  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (password.length < 8) {
    res.status(400).json({ message: DECRYPT_KEY_MESSAGE });
    return;
  }

  try {
    const archive = await getArchiveById(id);
    if (!archive) {
      res.status(404).json({ message: 'Arsip tidak ditemukan' });
      return;
    }
    if (!canAccessArchive(req.user, archive)) {
      res.status(403).json({ message: 'Akses ditolak' });
      return;
    }

    const container = await readEncrypted(archive.stored_name);
    const { data, metadata } = await decryptFileContainer({ container, password });
    try {
      await logActivity({ userId: req.user.id, archiveId: id, activity: 'DECRYPT', result: 'SUCCESS' });
    } catch {
      // best effort
    }
    const originalName = sanitizeOriginalName(metadata.originalName || archive.original_name);
    const ext = extensionOf(originalName) || archive.file_ext;

    try {
      await logActivity({ userId: req.user.id, archiveId: id, activity: 'DOWNLOAD', result: 'SUCCESS' });
    } catch {
      // best effort
    }

    res.setHeader('Content-Type', mimeForExtension(ext));
    res.setHeader('Content-Disposition', attachmentHeader(originalName));
    res.setHeader('Content-Length', data.length);
    res.setHeader('X-Integrity', 'verified');
    res.setHeader('X-Original-Size', data.length);
    res.setHeader('Cache-Control', 'no-store');
    res.status(200).send(data);
  } catch (error) {
    try {
      if (error instanceof ContainerError || error instanceof ArchiveCryptoError) {
        await logActivity({ userId: req.user?.id, archiveId: id, activity: 'DECRYPT', result: 'FAILED' });
        await logActivity({ userId: req.user?.id, archiveId: id, activity: 'DOWNLOAD', result: 'FAILED' });
      }
    } catch {
      // best effort
    }
    sendCryptoError(error, res, next);
  }
});

router.delete('/:id', async (req, res, next) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ message: 'ID arsip tidak valid' });
    return;
  }

  try {
    const archive = await getArchiveById(id);
    if (!archive) {
      res.status(404).json({ message: 'Arsip tidak ditemukan' });
      return;
    }
    if (!canAccessArchive(req.user, archive)) {
      res.status(403).json({ message: 'Akses ditolak' });
      return;
    }

    await deleteArchiveRecord(id);

    let fileCleanupWarning = false;
    try {
      await deleteEncrypted(archive.stored_name);
    } catch (storageError) {
      if (storageError?.code !== 'ENOENT') {
        fileCleanupWarning = true;
        console.error('Failed to delete encrypted archive file after DB delete', {
          archiveId: id,
          storedName: archive.stored_name,
          message: storageError?.message,
        });
      }
    }

    try {
      await logActivity({ userId: req.user.id, archiveId: id, activity: 'DELETE', result: 'SUCCESS' });
    } catch {
      // best effort
    }

    res.status(200).json({
      message: fileCleanupWarning
        ? 'Arsip berhasil dihapus, tetapi berkas terenkripsi gagal dibersihkan'
        : 'Arsip berhasil dihapus',
    });
  } catch (error) {
    next(error);
  }
});

export default router;
