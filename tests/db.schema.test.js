import { describe, expect, it, vi } from 'vitest';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.resolve(__dirname, '../src/db/schema.sql');

describe('db schema', () => {
  it('contains required tables, columns, enums, indexes, and FKs', async () => {
    const sql = await fs.readFile(schemaPath, 'utf8');

    expect(sql).toMatch(/CREATE TABLE IF NOT EXISTS\s+users/i);
    expect(sql).toMatch(/CREATE TABLE IF NOT EXISTS\s+archives/i);
    expect(sql).toMatch(/CREATE TABLE IF NOT EXISTS\s+activity_logs/i);

    expect(sql).toMatch(/username\s+VARCHAR\(\d+\)\s+NOT NULL/i);
    expect(sql).toMatch(/UNIQUE[\s\S]*username|username[\s\S]*UNIQUE/i);
    expect(sql).toMatch(/role\s+ENUM\(\s*'admin'\s*,\s*'pegawai'\s*\)/i);
    expect(sql).toMatch(/is_active\s+TINYINT\(1\)/i);

    expect(sql).toMatch(/archives[\s\S]*user_id/i);
    expect(sql).toMatch(/original_name/i);
    expect(sql).toMatch(/stored_name/i);
    expect(sql).toMatch(/file_ext/i);
    expect(sql).toMatch(/original_size/i);
    expect(sql).toMatch(/encrypted_size/i);
    expect(sql).toMatch(/sha256\s+CHAR\(64\)/i);
    expect(sql).toMatch(/salt\s+CHAR\(32\)/i);
    expect(sql).toMatch(/iv\s+CHAR\(32\)/i);
    expect(sql).toMatch(/created_at/i);

    expect(sql).toMatch(/activity_logs[\s\S]*user_id/i);
    expect(sql).toMatch(/activity_logs[\s\S]*archive_id[\s\S]*NULL/i);
    expect(sql).toMatch(/activity/i);
    expect(sql).toMatch(/result/i);

    expect(sql).toMatch(/FOREIGN KEY\s*\(\s*user_id\s*\)\s*REFERENCES\s+users/i);
    expect(sql).toMatch(/FOREIGN KEY\s*\(\s*archive_id\s*\)\s*REFERENCES\s+archives/i);
    expect(sql).toMatch(/INDEX|KEY/i);
  });
});
