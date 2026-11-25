import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const backendRoot = path.resolve(import.meta.dirname, '..');

describe('security defaults', () => {
  it('does not serve storage path statically', () => {
    const appSource = readFileSync(path.join(backendRoot, 'src/app.js'), 'utf8');
    expect(appSource).not.toMatch(/express\.static/);
    expect(appSource).not.toMatch(/STORAGE_PATH/);
  });

  it('archive download uses POST body password, no key in URL pattern', () => {
    const archivesRoute = readFileSync(path.join(backendRoot, 'src/routes/archives.js'), 'utf8');
    expect(archivesRoute).toMatch(/router\.post\(['"]\/:id\/download['"]/);
    expect(archivesRoute).not.toMatch(/router\.get\(['"]\/:id\/download/);
    expect(archivesRoute).not.toMatch(/req\.query\.(password|key|passphrase)/);
    expect(archivesRoute).not.toMatch(/req\.params\.(password|key|passphrase)/);
  });
});
