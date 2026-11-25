import 'dotenv/config';
import { app } from './app.js';
import { ensureStorageDir } from './services/storage.js';

const port = Number(process.env.PORT ?? 3000);

await ensureStorageDir();
app.listen(port, () => {
  console.log(`Server arsip digital berjalan di http://localhost:${port}`);
});
