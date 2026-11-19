/**
 * Tests for filesystem confinement (safe-paths.ts) and its use by the raw
 * MIME builder. A temp directory stands in for ~/Downloads/gmail-mcp.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveSaveDir, writeFileNoClobber, resolveReadableFile, FILES_DIR } from './safe-paths.js';
import { createEmailWithNodemailer } from './utl.js';

let root: string;      // scratch area holding both the files dir and an "outside" dir
let filesDir: string;  // the confined directory
let outside: string;   // a sibling directory that must never be reachable
let secret: string;    // a file outside the confined directory

beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'safe-paths-')));
    filesDir = path.join(root, 'files');
    outside = path.join(root, 'outside');
    fs.mkdirSync(outside);
    secret = path.join(outside, 'id_ed25519');
    fs.writeFileSync(secret, 'PRIVATE KEY');
});

afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
});

describe('FILES_DIR', () => {
    it('is ~/Downloads/gmail-mcp', () => {
        expect(FILES_DIR).toBe(path.join(os.homedir(), 'Downloads', 'gmail-mcp'));
    });
});

describe('resolveSaveDir', () => {
    it('defaults to the files dir and creates it', () => {
        expect(resolveSaveDir(undefined, filesDir)).toBe(filesDir);
        expect(fs.statSync(filesDir).isDirectory()).toBe(true);
    });

    it('resolves relative paths inside the files dir', () => {
        expect(resolveSaveDir('invoices/2026', filesDir)).toBe(path.join(filesDir, 'invoices', '2026'));
    });

    it('accepts an absolute path inside the files dir', () => {
        expect(resolveSaveDir(path.join(filesDir, 'a'), filesDir)).toBe(path.join(filesDir, 'a'));
    });

    it('rejects absolute paths outside the files dir', () => {
        expect(() => resolveSaveDir(outside, filesDir)).toThrow(/must be inside/);
        expect(() => resolveSaveDir(os.homedir(), filesDir)).toThrow(/must be inside/);
        expect(() => resolveSaveDir('/tmp', filesDir)).toThrow(/must be inside/);
    });

    it('rejects ../ traversal', () => {
        expect(() => resolveSaveDir('../outside', filesDir)).toThrow(/must be inside/);
        expect(() => resolveSaveDir('a/../../outside', filesDir)).toThrow(/must be inside/);
    });

    it('rejects a sibling whose name merely starts with the files dir name', () => {
        fs.mkdirSync(filesDir + '-evil');
        expect(() => resolveSaveDir(filesDir + '-evil', filesDir)).toThrow(/must be inside/);
    });

    it('rejects a symlinked subdirectory pointing outside, without creating anything there', () => {
        fs.mkdirSync(filesDir);
        fs.symlinkSync(outside, path.join(filesDir, 'link'));
        expect(() => resolveSaveDir('link', filesDir)).toThrow(/must be inside/);
        expect(() => resolveSaveDir('link/new/deeper', filesDir)).toThrow(/must be inside/);
        expect(fs.existsSync(path.join(outside, 'new'))).toBe(false);
    });
});

describe('writeFileNoClobber', () => {
    beforeEach(() => fs.mkdirSync(filesDir));

    it('writes a new file', () => {
        const p = writeFileNoClobber(filesDir, 'report.pdf', Buffer.from('x'));
        expect(p).toBe(path.join(filesDir, 'report.pdf'));
        expect(fs.readFileSync(p, 'utf8')).toBe('x');
    });

    it('never overwrites; adds a numeric suffix instead', () => {
        writeFileNoClobber(filesDir, 'report.pdf', 'first');
        const second = writeFileNoClobber(filesDir, 'report.pdf', 'second');
        const third = writeFileNoClobber(filesDir, 'report.pdf', 'third');
        expect(path.basename(second)).toBe('report (1).pdf');
        expect(path.basename(third)).toBe('report (2).pdf');
        expect(fs.readFileSync(path.join(filesDir, 'report.pdf'), 'utf8')).toBe('first');
    });

    it('strips directory components from the filename', () => {
        const p = writeFileNoClobber(filesDir, '../../outside/.zshrc', 'pwned');
        expect(p).toBe(path.join(filesDir, '.zshrc'));
        expect(fs.existsSync(path.join(outside, '.zshrc'))).toBe(false);
    });

    it('does not follow a pre-existing symlink at the target name', () => {
        fs.symlinkSync(secret, path.join(filesDir, 'evil.txt'));
        const p = writeFileNoClobber(filesDir, 'evil.txt', 'overwrite');
        expect(path.basename(p)).toBe('evil (1).txt');
        expect(fs.readFileSync(secret, 'utf8')).toBe('PRIVATE KEY');
    });

    it('rejects empty / dot filenames', () => {
        expect(() => writeFileNoClobber(filesDir, '', 'x')).toThrow(/Invalid filename/);
        expect(() => writeFileNoClobber(filesDir, '..', 'x')).toThrow(/Invalid filename/);
    });
});

describe('resolveReadableFile', () => {
    beforeEach(() => {
        fs.mkdirSync(filesDir);
        fs.writeFileSync(path.join(filesDir, 'ok.txt'), 'hello');
    });

    it('accepts files inside the files dir (absolute or relative)', () => {
        expect(resolveReadableFile(path.join(filesDir, 'ok.txt'), filesDir)).toBe(path.join(filesDir, 'ok.txt'));
        expect(resolveReadableFile('ok.txt', filesDir)).toBe(path.join(filesDir, 'ok.txt'));
    });

    it('rejects files outside the files dir', () => {
        expect(() => resolveReadableFile(secret, filesDir)).toThrow(/Only files inside/);
        expect(() => resolveReadableFile('../outside/id_ed25519', filesDir)).toThrow(/Only files inside/);
    });

    it('rejects a symlink inside the files dir that points outside', () => {
        fs.symlinkSync(secret, path.join(filesDir, 'innocent.txt'));
        expect(() => resolveReadableFile('innocent.txt', filesDir)).toThrow(/Only files inside/);
    });

    it('rejects the files dir itself and subdirectories', () => {
        fs.mkdirSync(path.join(filesDir, 'sub'));
        expect(() => resolveReadableFile(filesDir, filesDir)).toThrow(/Only files inside/);
        expect(() => resolveReadableFile('sub', filesDir)).toThrow(/Not a regular file/);
    });

    it('reports missing files', () => {
        expect(() => resolveReadableFile('nope.txt', filesDir)).toThrow(/does not exist/);
    });

    it('rejects URLs', () => {
        expect(() => resolveReadableFile('https://example.com/x.png', filesDir)).toThrow(/does not exist/);
    });
});

describe('createEmailWithNodemailer confinement', () => {
    const base = { to: ['recipient@example.com'], subject: 's', body: 'b' };

    beforeEach(() => {
        fs.mkdirSync(filesDir);
        fs.writeFileSync(path.join(filesDir, 'notes.txt'), 'attached content');
    });

    it('attaches files from the files dir', async () => {
        const raw = await createEmailWithNodemailer({ ...base, attachments: ['notes.txt'] }, filesDir);
        expect(raw).toMatch(/filename=notes\.txt/);
        expect(raw).toContain(Buffer.from('attached content').toString('base64'));
    });

    it('refuses to attach files outside the files dir', async () => {
        await expect(
            createEmailWithNodemailer({ ...base, attachments: [secret] }, filesDir),
        ).rejects.toThrow(/Only files inside/);
    });

    it('refuses inline images outside the files dir', async () => {
        await expect(
            createEmailWithNodemailer(
                { ...base, htmlBody: '<img src="cid:x">', inlineImages: [{ cid: 'x', path: secret }] },
                filesDir,
            ),
        ).rejects.toThrow(/Only files inside/);
    });
});
