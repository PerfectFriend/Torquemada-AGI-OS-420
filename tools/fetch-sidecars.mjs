#!/usr/bin/env node
// Downloads the pinned sidecar binaries (sing-box), verifies SHA-256 against tools/sidecars.lock.json and
// places them where Tauri's bundle.externalBin expects them: src-tauri/binaries/<name>-<target-triple>[.exe]
// Usage: node tools/fetch-sidecars.mjs [--target <triple>] [--all] [--cache <dir>]
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const lock = JSON.parse(fs.readFileSync(path.join(root, 'tools', 'sidecars.lock.json'), 'utf8'));
const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const cache = opt('--cache') || path.join(root, '.cache', 'sidecars');
const binDir = path.join(root, 'app', 'src-tauri', 'binaries');
const licDir = path.join(root, 'app', 'src-tauri', 'licenses');

function hostTriple() {
  try { const m = /host:\s*(\S+)/.exec(execFileSync('rustc', ['-vV'], { encoding: 'utf8' })); if (m) return m[1]; } catch {}
  const a = { x64: 'x86_64', arm64: 'aarch64' }[os.arch()];
  const p = { linux: 'unknown-linux-gnu', darwin: 'apple-darwin', win32: 'pc-windows-msvc' }[os.platform()];
  if (!a || !p) throw new Error('не удалось определить платформу, укажите --target');
  return `${a}-${p}`;
}
const sha256 = (f) => createHash('sha256').update(fs.readFileSync(f)).digest('hex');

async function download(url, dest) {
  const r = await fetch(url, { redirect: 'follow' });
  if (!r.ok) throw new Error(`HTTP ${r.status} для ${url}`);
  fs.writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
}
function extract(archive, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  try { execFileSync('tar', ['-xf', archive, '-C', outDir], { stdio: 'pipe' }); }       // bsdtar (Windows, macOS) and GNU tar for .tar.gz
  catch (e) { if (archive.endsWith('.zip')) execFileSync('unzip', ['-q', '-o', archive, '-d', outDir], { stdio: 'pipe' }); else throw e; }
}
function findFile(dir, name) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { const r = findFile(p, name); if (r) return r; } else if (e.name === name) return p;
  }
  return null;
}

async function fetchOne(name, spec, triple) {
  const a = spec.assets[triple];
  if (!a) throw new Error(`${name}: нет сборки для ${triple}`);
  const exe = triple.includes('windows') ? '.exe' : '';
  const out = path.join(binDir, `${name}-${triple}${exe}`);
  fs.mkdirSync(cache, { recursive: true }); fs.mkdirSync(binDir, { recursive: true }); fs.mkdirSync(licDir, { recursive: true });
  const file = path.join(cache, a.file);
  if (!fs.existsSync(file) || sha256(file) !== a.sha256) {
    console.log(`[fetch] ${a.file}`);
    await download(spec.url_base + a.file, file);
  }
  const got = sha256(file);
  if (got !== a.sha256) { fs.rmSync(file, { force: true }); throw new Error(`${name}: SHA-256 не совпал для ${a.file}\n  ожидалось ${a.sha256}\n  получено   ${got}`); }
  const tmp = path.join(cache, `x-${name}-${triple}`);
  fs.rmSync(tmp, { recursive: true, force: true }); extract(file, tmp);
  const bin = findFile(tmp, name + exe);
  if (!bin) throw new Error(`${name}${exe} не найден в архиве`);
  fs.copyFileSync(bin, out); if (!exe) fs.chmodSync(out, 0o755);
  const lic = findFile(tmp, 'LICENSE'); if (lic) fs.copyFileSync(lic, path.join(licDir, `${name}-LICENSE.txt`));
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`[ok]    ${path.relative(root, out)}  (${name} ${spec.version}, SHA-256 проверен)`);
}

const triples = args.includes('--all') ? Object.keys(lock['sing-box'].assets) : [opt('--target') || hostTriple()];
for (const t of triples) for (const [name, spec] of Object.entries(lock).filter(([k]) => !k.startsWith('_'))) await fetchOne(name, spec, t);
