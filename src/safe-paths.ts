/**
 * Filesystem confinement for every tool that reads or writes local files.
 *
 * Email content is untrusted input to the model driving this server, so a
 * prompt-injected tool call must not be able to:
 *   - attach arbitrary local files (SSH keys, OAuth tokens, kubeconfigs) to an
 *     outgoing email, or
 *   - write attacker-supplied attachment bytes to arbitrary paths (~/.zshrc).
 *
 * All file access is therefore confined to FILES_DIR. Paths are checked after
 * resolving symlinks, and writes never overwrite an existing file.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const FILES_DIR = path.join(os.homedir(), 'Downloads', 'gmail-mcp');

/** Display form of a path for error messages (home directory shown as ~). */
function display(p: string): string {
    const home = os.homedir();
    return p === home || p.startsWith(home + path.sep) ? '~' + p.slice(home.length) : p;
}

function expandHome(p: string): string {
    if (p === '~') return os.homedir();
    if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
    return p;
}

/** True when `target` is `base` or a descendant of it (both must be absolute and normalized). */
function isInside(base: string, target: string): boolean {
    const rel = path.relative(base, target);
    return rel === '' || (rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel));
}

/** Create the files directory if needed and return its real (symlink-resolved) path. */
export function ensureFilesDir(baseDir: string = FILES_DIR): string {
    fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 });
    return fs.realpathSync(baseDir);
}

/**
 * Resolve a directory to save into. `savePath` may be omitted (the files dir
 * itself), relative (resolved against the files dir), or absolute; either way
 * the result must lie inside the files dir after resolving symlinks. The
 * directory is created if missing.
 */
export function resolveSaveDir(savePath: string | undefined, baseDir: string = FILES_DIR): string {
    const base = ensureFilesDir(baseDir);
    const lexicalBase = path.resolve(baseDir);
    const requested = savePath ? path.resolve(base, expandHome(savePath)) : base;

    const outside = () =>
        new Error(`savePath must be inside ${display(lexicalBase)}: ${savePath}`);

    if (!isInside(base, requested) && !isInside(lexicalBase, requested)) {
        throw outside();
    }

    // Check the deepest existing ancestor before creating anything, so a
    // symlinked subdirectory cannot make mkdir create directories elsewhere.
    let existing = requested;
    while (!fs.existsSync(existing)) {
        existing = path.dirname(existing);
    }
    if (!isInside(base, fs.realpathSync(existing))) {
        throw outside();
    }

    fs.mkdirSync(requested, { recursive: true, mode: 0o700 });
    const real = fs.realpathSync(requested);
    if (!isInside(base, real)) {
        throw outside();
    }
    if (!fs.statSync(real).isDirectory()) {
        throw new Error(`savePath is not a directory: ${savePath}`);
    }
    return real;
}

/**
 * Write `data` into `dir` without ever replacing an existing file. Only the
 * final path component of `filename` is used. On a name collision a numeric
 * suffix is added ("report (1).pdf"). Returns the path written.
 *
 * The 'wx' flag (O_CREAT | O_EXCL) also refuses to follow a pre-existing
 * symlink at the target path.
 */
export function writeFileNoClobber(dir: string, filename: string, data: string | Buffer): string {
    const safeName = path.basename(filename);
    if (!safeName || safeName === '.' || safeName === '..') {
        throw new Error(`Invalid filename: ${filename}`);
    }
    const ext = path.extname(safeName);
    const stem = safeName.slice(0, safeName.length - ext.length);

    for (let i = 0; i < 1000; i++) {
        const candidate = path.join(dir, i === 0 ? safeName : `${stem} (${i})${ext}`);
        try {
            fs.writeFileSync(candidate, data, { flag: 'wx', mode: 0o600 });
            return candidate;
        } catch (err: any) {
            if (err?.code !== 'EEXIST') throw err;
        }
    }
    throw new Error(`Could not find a free filename for ${safeName} in ${display(dir)}`);
}

/**
 * Resolve a file that will be read and sent (attachment or inline image).
 * Relative paths resolve against the files dir. The symlink-resolved path must
 * be a regular file inside the files dir.
 */
export function resolveReadableFile(filePath: string, baseDir: string = FILES_DIR): string {
    const base = ensureFilesDir(baseDir);
    const requested = path.resolve(base, expandHome(filePath));

    let real: string;
    try {
        real = fs.realpathSync(requested);
    } catch {
        throw new Error(`File does not exist: ${filePath}`);
    }
    if (!isInside(base, real) || real === base) {
        throw new Error(
            `Only files inside ${display(path.resolve(baseDir))} can be attached: ${filePath}. ` +
            `Ask the user to copy the file there first.`,
        );
    }
    if (!fs.statSync(real).isFile()) {
        throw new Error(`Not a regular file: ${filePath}`);
    }
    return real;
}
