import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { CANARY_PROFILE, INSIDE_MARKER, NETWORK_MARKER, PermissionsCanaryError,
  buildCanarySandboxArgs, canaryProfileOverrides, evaluateCanary } from './codex-harness-permissions-canary.mjs';

// Pure fixtures only. These tests never start a real CLI, socket or model.
const originalFetch = globalThis.fetch;
before(() => { globalThis.fetch = async () => { throw new Error('NETWORK_DISABLED_IN_TEST'); }; });
after(() => { globalThis.fetch = originalFetch; });
const denied = () => ({ code: 1, stdout: '' });
const passing = () => ({
  inside: { code: 0, stdout: INSIDE_MARKER }, outside: denied(), symlink: denied(), create: denied(), modify: denied(),
  slashTemporaryOutside: denied(), slashTemporarySymlink: denied(),
  networkControl: { code: 0, stdout: NETWORK_MARKER }, networkRuntime: { code: 0, stdout: 'curl synthetic-version' },
  network: denied(), insideUnchanged: true, createdFileAbsent: true,
});

test('canary chooses a named restrictive profile without any legacy sandbox override', () => {
  const args = buildCanarySandboxArgs('/tmp/synthetic/workspace', ['/bin/cat', '/tmp/synthetic/workspace/input.txt']);
  assert.deepEqual(args, ['sandbox', '--permission-profile', CANARY_PROFILE, '--include-managed-config', '--cd', '/tmp/synthetic/workspace',
    ...canaryProfileOverrides().flatMap(value => ['-c', value]), '--', '/bin/cat', '/tmp/synthetic/workspace/input.txt']);
  const config = canaryProfileOverrides().join('\n');
  assert.match(config, /":root"="deny"/);
  assert.match(config, /":minimal"="read"/);
  assert.match(config, /":tmpdir"="deny"/);
  assert.match(config, /":slash_tmp"="deny"/);
  assert.match(config, /":workspace_roots"=\{ "\."="read" \}/);
  assert.match(config, /network\.enabled=false/);
  assert.doesNotMatch(config, /sandbox_mode|network\.enabled=true|="write"|base_url|auth|token|api_key/);
});

test('relative paths, absent native command and malformed command arguments are rejected', () => {
  for (const [workspace, command] of [
    ['relative', ['/bin/cat']], [null, ['/bin/cat']], ['/tmp/workspace', []], ['/tmp/workspace', ['relative']],
    ['/tmp/workspace', [null]],
    ['/tmp/workspace', ['/bin/cat', 'bad\0path']], ['/tmp/workspace', ['/bin/cat', null]],
  ]) assert.throws(() => buildCanarySandboxArgs(workspace, command), { code: 'INVALID_OPTIONS' });
});

test('only successful inside read plus separate denied read/write/network controls produce a safe receipt', () => {
  const receipt = evaluateCanary(passing());
  assert.deepEqual(receipt, { status: 'PERMISSION_CANARY_PASSED', permissionProfile: CANARY_PROFILE,
    scope: 'temporary_synthetic_files_and_loopback', insideReadAllowed: true, outsideFixtureReadDenied: true,
    outsideSymlinkReadDenied: true, slashTemporaryFixtureReadDenied: true, slashTemporarySymlinkReadDenied: true,
    workspaceCreateDenied: true, workspaceModifyDenied: true,
    networkControlVerified: true, sandboxNetworkToolStarted: true, loopbackNetworkDenied: true,
    modelRequestsMade: 0, existingAuthCacheRead: false });
  assert.ok(Object.isFrozen(receipt));
});

test('a missing, signalled or failing inside command cannot masquerade as successful denial elsewhere', () => {
  for (const inside of [undefined, { code: null, stdout: INSIDE_MARKER }, { code: 1, stdout: INSIDE_MARKER },
    { code: 0, stdout: '' }, { code: 0, stdout: `${INSIDE_MARKER}\nextra` }]) {
    assert.throws(() => evaluateCanary({ ...passing(), inside }), { code: 'INSIDE_READ_FAILED' });
  }
});

test('every outside, symlink, creation, modification and network boundary fails closed independently', async t => {
  for (const [field, code] of [['outside', 'OUTSIDE_READ_ALLOWED'], ['symlink', 'SYMLINK_READ_ALLOWED'],
    ['slashTemporaryOutside', 'SLASH_TMP_READ_ALLOWED'], ['slashTemporarySymlink', 'SLASH_TMP_SYMLINK_READ_ALLOWED'],
    ['create', 'CREATE_ALLOWED'], ['modify', 'MODIFY_ALLOWED'], ['network', 'NETWORK_ALLOWED']]) {
    for (const [label, observation] of [['successful command', { code: 0, stdout: '' }],
      ['partial leak despite nonzero exit', { code: 1, stdout: 'synthetic-private-marker' }],
      ['signal exit', { code: null, stdout: '' }], ['absent result', undefined]]) {
      await t.test(`${field}: ${label}`, () => assert.throws(() => evaluateCanary({ ...passing(), [field]: observation }), { code }));
    }
  }
});

test('filesystem postconditions detect writes even if the child reports failure', () => {
  assert.throws(() => evaluateCanary({ ...passing(), createdFileAbsent: false }), { code: 'CREATE_ALLOWED' });
  assert.throws(() => evaluateCanary({ ...passing(), insideUnchanged: false }), { code: 'MODIFY_ALLOWED' });
});

test('network denial is never accepted without a successful same-listener baseline', () => {
  for (const networkControl of [undefined, { code: 7, stdout: '' }, { code: 0, stdout: '' },
    { code: 0, stdout: `${NETWORK_MARKER}\nnot-exact` }]) {
    assert.throws(() => evaluateCanary({ ...passing(), networkControl }), { code: 'NETWORK_CONTROL_FAILED' });
  }
});

test('a blocked or broken curl executable cannot be mistaken for denied network access', () => {
  for (const networkRuntime of [undefined, { code: 1, stdout: '' }, { code: 0, stdout: '' },
    { code: 0, stdout: null }, { code: 0 }, { code: null, stdout: 'curl fixture' }]) {
    assert.throws(() => evaluateCanary({ ...passing(), networkRuntime }), { code: 'NETWORK_RUNTIME_FAILED' });
  }
});

test('errors and receipts cannot expose arbitrary command error text or synthetic file contents', () => {
  const marker = 'synthetic-private-value-not-for-receipt';
  const error = new PermissionsCanaryError(marker);
  assert.equal(error.code, 'FIXTURE_FAILED');
  assert.equal(error.message, 'FIXTURE_FAILED');
  assert.doesNotMatch(JSON.stringify(error), /synthetic-private-value/);
  const input = { ...passing(), stderr: marker, authToken: marker, outsidePath: `/tmp/${marker}` };
  assert.doesNotMatch(JSON.stringify(evaluateCanary(input)), /synthetic-private-value|authToken|outsidePath|stderr/);
});
