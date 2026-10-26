#!/usr/bin/env node
// Credential-free native sandbox canary. It reads only files created below,
// invokes no model/auth endpoint and exposes no inference or HTTP gateway.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { createServer } from 'node:http';
import { mkdir, mkdtemp, readFile, realpath, rm, lstat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const CANARY_PROFILE = 'corely-synthetic-read';
export const INSIDE_MARKER = 'Corely synthetic workspace input.';
export const NETWORK_MARKER = 'Corely loopback canary control.';
const OUTSIDE_MARKER = 'Corely synthetic outside fixture.';
const WRITE_MARKER = 'Corely synthetic write attempt.';
const ERROR_CODES = new Set(['INVALID_OPTIONS', 'UNSUPPORTED_PLATFORM', 'FIXTURE_FAILED', 'SPAWN_FAILED', 'TIMEOUT',
  'OUTPUT_LIMIT', 'INSIDE_READ_FAILED', 'OUTSIDE_READ_ALLOWED', 'SYMLINK_READ_ALLOWED',
  'SLASH_TMP_READ_ALLOWED', 'SLASH_TMP_SYMLINK_READ_ALLOWED', 'CREATE_ALLOWED',
  'MODIFY_ALLOWED', 'NETWORK_CONTROL_FAILED', 'NETWORK_RUNTIME_FAILED', 'NETWORK_ALLOWED', 'RUNTIME_CHANGED']);

export class PermissionsCanaryError extends Error {
  constructor(code) { super(ERROR_CODES.has(code) ? code : 'FIXTURE_FAILED'); this.code = this.message; }
}

// Reusable profile definition: no legacy sandbox_mode or --sandbox override.
// Minimal platform files remain readable so the fixed native tools can start.
// That preset also includes temporary trees: deny both generic temporary roots
// before reopening only the selected workspace. Do not substitute exact fixture
// paths here; the same policy is consumed by later candidate threads.
export function canaryProfileOverrides() {
  return [
    `default_permissions="${CANARY_PROFILE}"`,
    `permissions.${CANARY_PROFILE}.filesystem={ ":root"="deny", ":minimal"="read", ":tmpdir"="deny", ":slash_tmp"="deny", ":workspace_roots"={ "."="read" } }`,
    `permissions.${CANARY_PROFILE}.network.enabled=false`,
  ];
}

export function buildCanarySandboxArgs(workspace, command) {
  if (typeof workspace !== 'string' || !isAbsolute(workspace) || !Array.isArray(command) || !command.length ||
      typeof command[0] !== 'string' || !isAbsolute(command[0]) ||
      command.some(value => typeof value !== 'string' || value.includes('\0'))) throw new PermissionsCanaryError('INVALID_OPTIONS');
  return ['sandbox', '--permission-profile', CANARY_PROFILE, '--include-managed-config', '--cd', workspace,
    ...canaryProfileOverrides().flatMap(value => ['-c', value]), '--', ...command];
}

// Receipt only. Never expose command stderr, filesystem contents or paths.
export function evaluateCanary(observations) {
  const ok = result => result?.code === 0;
  const denied = result => Number.isInteger(result?.code) && result.code !== 0 && result.stdout === '';
  if (!ok(observations?.inside) || observations.inside.stdout !== INSIDE_MARKER) throw new PermissionsCanaryError('INSIDE_READ_FAILED');
  if (!denied(observations?.outside)) throw new PermissionsCanaryError('OUTSIDE_READ_ALLOWED');
  if (!denied(observations?.symlink)) throw new PermissionsCanaryError('SYMLINK_READ_ALLOWED');
  if (!denied(observations?.slashTemporaryOutside)) throw new PermissionsCanaryError('SLASH_TMP_READ_ALLOWED');
  if (!denied(observations?.slashTemporarySymlink)) throw new PermissionsCanaryError('SLASH_TMP_SYMLINK_READ_ALLOWED');
  if (!denied(observations?.create) || observations.createdFileAbsent !== true) throw new PermissionsCanaryError('CREATE_ALLOWED');
  if (!denied(observations?.modify) || observations.insideUnchanged !== true) throw new PermissionsCanaryError('MODIFY_ALLOWED');
  if (!ok(observations?.networkControl) || observations.networkControl.stdout !== NETWORK_MARKER) {
    throw new PermissionsCanaryError('NETWORK_CONTROL_FAILED');
  }
  if (!ok(observations?.networkRuntime) || typeof observations.networkRuntime.stdout !== 'string' ||
      !observations.networkRuntime.stdout.startsWith('curl ')) {
    throw new PermissionsCanaryError('NETWORK_RUNTIME_FAILED');
  }
  if (!denied(observations?.network)) throw new PermissionsCanaryError('NETWORK_ALLOWED');
  return Object.freeze({ status: 'PERMISSION_CANARY_PASSED', permissionProfile: CANARY_PROFILE,
    scope: 'temporary_synthetic_files_and_loopback', insideReadAllowed: true, outsideFixtureReadDenied: true,
    outsideSymlinkReadDenied: true, slashTemporaryFixtureReadDenied: true, slashTemporarySymlinkReadDenied: true,
    workspaceCreateDenied: true, workspaceModifyDenied: true,
    networkControlVerified: true, sandboxNetworkToolStarted: true, loopbackNetworkDenied: true,
    modelRequestsMade: 0, existingAuthCacheRead: false });
}

// Public executable bytes only, never credential/config/session paths. The
// caller can compare this digest before a later adapter turn to detect updates.
export async function canaryExecutableSha256(executable) {
  if (typeof executable !== 'string' || !isAbsolute(executable)) throw new PermissionsCanaryError('INVALID_OPTIONS');
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(executable)) hash.update(chunk);
  return hash.digest('hex');
}

async function capture(executable, args, options) {
  const child = spawn(executable, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', bytes = 0, failure;
  const fail = code => { failure ??= new PermissionsCanaryError(code); child.kill('SIGTERM'); };
  const timer = setTimeout(() => fail('TIMEOUT'), 5000);
  const killer = setTimeout(() => child.kill('SIGKILL'), 6000);
  child.stdout.on('data', chunk => {
    bytes += chunk.length;
    if (bytes > 8192) return fail('OUTPUT_LIMIT');
    stdout += chunk.toString('utf8');
  });
  child.stderr.on('data', chunk => {
    bytes += chunk.length;
    if (bytes > 8192) fail('OUTPUT_LIMIT');
    // Deliberately do not retain stderr. Only fixed error codes leave here.
  });
  try {
    const code = await new Promise((done, reject) => {
      child.once('error', () => reject(new PermissionsCanaryError('SPAWN_FAILED')));
      child.once('close', done);
    });
    if (failure) throw failure;
    return { code, stdout };
  } finally { clearTimeout(timer); clearTimeout(killer); child.kill('SIGTERM'); }
}

export async function runPermissionsCanary({ executable, sourceEnv = process.env }) {
  if (typeof executable !== 'string' || !isAbsolute(executable)) throw new PermissionsCanaryError('INVALID_OPTIONS');
  if (!['darwin', 'linux'].includes(process.platform)) throw new PermissionsCanaryError('UNSUPPORTED_PLATFORM');
  const root = await realpath(await mkdtemp(join(tmpdir(), 'corely-permission-canary-')));
  const workspace = join(root, 'workspace'), home = join(root, 'empty-home'), codexHome = join(root, 'empty-codex-home');
  let server, slashTempRoot;
  try {
    const executableSha256 = await canaryExecutableSha256(executable);
    for (const directory of [workspace, home, codexHome]) await mkdir(directory, { mode: 0o700 });
    const inside = join(workspace, 'synthetic-input.txt'), outside = join(root, 'synthetic-outside.txt');
    const link = join(workspace, 'outside-link'), created = join(workspace, 'must-not-be-created.txt');
    await writeFile(inside, INSIDE_MARKER, { mode: 0o600 });
    await writeFile(outside, OUTSIDE_MARKER, { mode: 0o600 });
    await symlink(outside, link);
    // Separate generic /tmp control: on macOS this is not the per-user
    // :tmpdir tree. Its canonical path also tests /tmp -> /private/tmp.
    slashTempRoot = await realpath(await mkdtemp('/tmp/corely-permission-canary-outside-'));
    const slashTemporaryOutside = join(slashTempRoot, 'synthetic-outside.txt');
    const slashTemporaryLink = join(workspace, 'slash-tmp-outside-link');
    await writeFile(slashTemporaryOutside, OUTSIDE_MARKER, { mode: 0o600 });
    await symlink(slashTemporaryOutside, slashTemporaryLink);
    const env = { HOME: home, CODEX_HOME: codexHome, PATH: '/usr/bin:/bin' };
    for (const key of ['LANG', 'TZ']) if (typeof sourceEnv[key] === 'string') env[key] = sourceEnv[key];
    server = createServer((request, response) => {
      if (request.method !== 'GET' || request.url !== '/corely-synthetic-canary') {
        response.writeHead(404, { Connection: 'close' }); return response.end();
      }
      response.writeHead(200, { 'Content-Type': 'text/plain', Connection: 'close' }); response.end(NETWORK_MARKER);
    });
    await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
    const address = server.address();
    if (!address || typeof address !== 'object') throw new PermissionsCanaryError('FIXTURE_FAILED');
    const curl = ['/usr/bin/curl', '--disable', '--noproxy', '*', '--silent', '--show-error', '--fail', '--max-time', '2',
      `http://127.0.0.1:${address.port}/corely-synthetic-canary`];
    const options = { env, cwd: workspace };
    const networkControl = await capture(curl[0], curl.slice(1), options);
    // The live listener stays up through both controls. No external DNS or
    // destination is used, and only this fixed synthetic marker is served.
    const execute = command => capture(executable, buildCanarySandboxArgs(workspace, command), options);
    const observations = {
      networkControl,
      inside: await execute(['/bin/cat', inside]),
      outside: await execute(['/bin/cat', outside]),
      symlink: await execute(['/bin/cat', link]),
      slashTemporaryOutside: await execute(['/bin/cat', slashTemporaryOutside]),
      slashTemporarySymlink: await execute(['/bin/cat', slashTemporaryLink]),
      create: await execute(['/bin/sh', '-c', 'printf %s "$1" > "$2"', 'corely-canary', WRITE_MARKER, created]),
      modify: await execute(['/bin/sh', '-c', 'printf %s "$1" > "$2"', 'corely-canary', WRITE_MARKER, inside]),
      networkRuntime: await execute(['/usr/bin/curl', '--disable', '--version']),
      network: await execute(curl),
      insideUnchanged: (await readFile(inside, 'utf8')) === INSIDE_MARKER,
      createdFileAbsent: await lstat(created).then(() => false, error => {
        if (error.code === 'ENOENT') return true;
        throw new PermissionsCanaryError('FIXTURE_FAILED');
      }),
    };
    const receipt = evaluateCanary(observations);
    if (await canaryExecutableSha256(executable) !== executableSha256) throw new PermissionsCanaryError('RUNTIME_CHANGED');
    return Object.freeze({ ...receipt, executableSha256 });
  } catch (error) { throw error instanceof PermissionsCanaryError ? error : new PermissionsCanaryError('FIXTURE_FAILED'); }
  finally {
    if (server?.listening) await new Promise(done => { server.close(done); server.closeAllConnections(); });
    await rm(root, { recursive: true, force: true });
    if (slashTempRoot) await rm(slashTempRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--executable') throw new PermissionsCanaryError('INVALID_OPTIONS');
    process.stdout.write(`${JSON.stringify(await runPermissionsCanary({ executable: process.argv[3] }))}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ status: 'PERMISSION_CANARY_FAILED',
      code: error instanceof PermissionsCanaryError ? error.code : 'FIXTURE_FAILED', modelRequestsMade: 0 })}\n`);
    process.exitCode = 1;
  }
}
