import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { openCorelyDevGatewayCredentialRotation } from './siwc-gateway-credential-rotation.mjs';

const binding = { tenantId: 'moztech', brandId: 'moztech-test', syntheticOnly: true, apiFallbackEnabled: false, noPaidCredits: true };
const denied = code => error => error.code === code && error.message === code && error.cause === undefined;
const leaseAck = ({ generation, leaseId }) => ({ status: 'CORELY_DEV_GATEWAY_LEASE_SETTLED', generation, leaseId });
const commitAck = ({ previousGeneration, nextGeneration, previousBundleSha256, nextBundleSha256 }) =>
  ({ status: 'CORELY_DEV_GATEWAY_CREDENTIALS_COMMITTED', previousGeneration, nextGeneration, previousBundleSha256, nextBundleSha256, predecessorRetired: true });
const deferred = () => {
  let release;
  const promise = new Promise(resolve => { release = resolve; });
  return { promise, release };
};

async function syntheticTls(t) {
  const root = await mkdtemp(join(tmpdir(), 'corely-gateway-rotation-fixture-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const openssl = (...args) => execFileSync('openssl', args, { cwd: root, timeout: 5000, stdio: 'pipe' });
  const read = name => readFile(join(root, name), 'utf8');
  openssl('req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '2', '-subj', '/CN=Corely Synthetic Test CA',
    '-keyout', 'ca.key', '-out', 'ca.pem', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  const leaves = [];
  for (const [index, host] of ['corely-siwc-bridge', 'corely-siwc-bridge', 'foreign.example.test'].entries()) {
    const name = `leaf-${index}`;
    openssl('req', '-new', '-newkey', 'ed25519', '-nodes', '-subj', `/CN=${host}`, '-keyout', `${name}.key`, '-out', `${name}.csr`);
    await writeFile(join(root, 'ext'), `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${host}\n`);
    openssl('x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-set_serial', String(index + 1),
      '-days', '1', '-extfile', 'ext', '-out', `${name}.pem`);
    leaves.push({ tlsCertificatePem: await read(`${name}.pem`), tlsPrivateKeyPem: await read(`${name}.key`) });
  }
  return { bridgeCaPem: await read('ca.pem'), leaves };
}

function fixture(tls) {
  let wall = Date.now(), mono = 1000;
  const authority = { kind: 'CORELY_DEV_MODEL_GATEWAY_AUTHORITY_V1', authorityIdSha256: 'b'.repeat(64), expiresAt: wall + 120_000, ...binding };
  const version = (generation, index = generation - 1) => ({
    kind: 'CORELY_DEV_MODEL_GATEWAY_CREDENTIALS_V1', generation, authorityIdSha256: authority.authorityIdSha256,
    parentExpiresAt: authority.expiresAt, expiresAt: wall + 60_000,
    gatewayUrl: 'https://newapi-dev.corely.cc/v1/responses', bridgeHost: 'corely-siwc-bridge',
    gatewayToken: `SYNTHETIC_GATEWAY_TOKEN_${generation}_`.repeat(2),
    bridgeSecret: `SYNTHETIC_BRIDGE_SECRET_${generation}_`.repeat(2), ...tls.leaves[index], ...binding,
  });
  const signal = new AbortController();
  const options = { enabled: true, authority, bridgeCaPem: tls.bridgeCaPem, initial: version(1),
    signal: signal.signal, now: () => wall, monotonicNow: () => mono };
  return { options, version, signal, advanceWall: ms => { wall += ms; }, advanceMono: ms => { mono += ms; } };
}

test('disabled is side-effect-free and does not inspect secret-bearing options', () => {
  assert.throws(() => openCorelyDevGatewayCredentialRotation({ get authority() { assert.fail('must not read disabled source'); } }),
    denied('GATEWAY_ROTATION_DISABLED'));
});

test('unwired DEV route generation enforces credential trust, a single owned lease and confirmed CAS', async t => {
  const tls = await syntheticTls(t);
  await t.test('rejects no-model parent, foreign route, altered scope, replaced trust and reuse before any installer call', async () => {
    const f = fixture(tls);
    assert.throws(() => openCorelyDevGatewayCredentialRotation({ ...f.options, authority: {
      ...f.options.authority, kind: 'CORELY_VM_STANDING_AUTHORITY_ACTIVE',
    } }), denied('GATEWAY_ROTATION_AUTHORITY_INVALID'));
    assert.throws(() => openCorelyDevGatewayCredentialRotation({ ...f.options, bridgeCaPem: tls.leaves[0].tlsCertificatePem }),
      denied('GATEWAY_ROTATION_AUTHORITY_INVALID'));
    const adapter = openCorelyDevGatewayCredentialRotation(f.options);
    const forbidden = () => assert.fail('invalid credentials reached installer');
    for (const patch of [{ brandId: 'another' }, { authorityIdSha256: 'c'.repeat(64) }, { syntheticOnly: false }, { apiFallbackEnabled: true },
      { noPaidCredits: false }, { parentExpiresAt: f.options.authority.expiresAt + 1 }, { expiresAt: f.options.authority.expiresAt + 1 },
      { gatewayUrl: 'https://newapi-dev.corely.cc/v1/chat/completions' }, { bridgeHost: 'another' },
      { ...tls.leaves[2] }, { tlsPrivateKeyPem: tls.leaves[0].tlsPrivateKeyPem },
      { gatewayToken: f.options.initial.bridgeSecret }, { ...tls.leaves[0] }]) {
      await assert.rejects(adapter.replace(1, { ...f.version(2), ...patch }, forbidden), denied('GATEWAY_ROTATION_SNAPSHOT_INVALID'));
    }
    await assert.rejects(adapter.replace(0, f.version(2), forbidden), denied('GATEWAY_ROTATION_STALE'));
    await assert.rejects(adapter.replace(1, f.version(3, 1), forbidden), denied('GATEWAY_ROTATION_STALE'));
    assert.equal(adapter.receipt().generation, 1);
    adapter.close();
  });

  await t.test('drain pauses admission, one exact swap publishes only the successor; retired credentials cannot return', async () => {
    const f = fixture(tls), adapter = openCorelyDevGatewayCredentialRotation(f.options), started = deferred(), release = deferred();
    const first = adapter.withLease(async value => {
      assert.equal(value.credentials.gatewayToken, f.options.initial.gatewayToken);
      assert.equal(value.credentials.tlsPrivateKeyPem, f.options.initial.tlsPrivateKeyPem);
      started.release(); await release.promise;
      return leaseAck(value);
    });
    await started.promise;
    let commits = 0;
    const next = f.version(2), expectedToken = next.gatewayToken, replacement = adapter.replace(1, next, async value => {
      commits++;
      assert.equal(value.next.gatewayToken, expectedToken);
      assert.equal(value.next.bridgeSecret, next.bridgeSecret);
      assert.equal(value.next.tlsCertificatePem, next.tlsCertificatePem);
      assert.match(value.nextBundleSha256, /^[0-9a-f]{64}$/);
      return commitAck(value);
    });
    next.gatewayToken = 'MUTATION_MUST_NOT_CHANGE_STAGED_CREDENTIAL'.repeat(2);
    await assert.rejects(adapter.withLease(leaseAck), denied('GATEWAY_ROTATION_BUSY'));
    await assert.rejects(adapter.replace(1, f.version(2), commitAck), denied('GATEWAY_ROTATION_BUSY'));
    assert.equal(commits, 0); assert.equal(adapter.receipt().status, 'GATEWAY_ROTATION_DRAINING');
    release.release();
    assert.deepEqual(await first, { status: 'CORELY_DEV_GATEWAY_LEASE_SETTLED', generation: 1 });
    const rotated = await replacement;
    assert.equal(commits, 1); assert.equal(rotated.generation, 2); assert.equal(rotated.parentExpiresAt, f.options.authority.expiresAt);
    assert.doesNotMatch(JSON.stringify(rotated), /SYNTHETIC_(?:GATEWAY|BRIDGE)|PRIVATE KEY|bundle|authorityId/);
    await adapter.withLease(value => {
      assert.equal(value.credentials.gatewayToken, f.version(2).gatewayToken);
      return leaseAck(value);
    });
    await assert.rejects(adapter.replace(2, f.version(3, 0), commitAck), denied('GATEWAY_ROTATION_SNAPSHOT_INVALID'));
    adapter.close();
  });

  await t.test('unresolved work, lost/mismatched commit and deadline drift never resume predecessor or retry', async () => {
    for (const mode of ['uncertain commit', 'wrong bundle', 'missing retirement', 'late commit', 'revoked']) {
      const f = fixture(tls), adapter = openCorelyDevGatewayCredentialRotation(f.options);
      let commits = 0;
      await assert.rejects(adapter.replace(1, f.version(2), value => {
        commits++;
        if (mode === 'uncertain commit') throw new Error('PRIVATE_COMMIT_FAILURE');
        if (mode === 'wrong bundle') return { ...commitAck(value), nextBundleSha256: '0'.repeat(64) };
        if (mode === 'missing retirement') return { ...commitAck(value), predecessorRetired: false };
        if (mode === 'late commit') f.advanceMono(60_000);
        if (mode === 'revoked') f.signal.abort();
        return commitAck(value);
      }), denied('GATEWAY_ROTATION_HELD'));
      assert.equal(commits, 1);
      await assert.rejects(adapter.replace(1, f.version(2), commitAck), denied('GATEWAY_ROTATION_HELD'));
      await assert.rejects(adapter.withLease(leaseAck), denied('GATEWAY_ROTATION_HELD'));
    }
    const f = fixture(tls), adapter = openCorelyDevGatewayCredentialRotation(f.options), release = deferred();
    const lease = adapter.withLease(async value => { await release.promise; return { ...leaseAck(value), leaseId: 'old-lease' }; });
    const replacing = adapter.replace(1, f.version(2), () => assert.fail('unresolved owner must not reach installer'));
    release.release();
    await assert.rejects(lease, denied('GATEWAY_ROTATION_HELD'));
    await assert.rejects(replacing, denied('GATEWAY_ROTATION_HELD'));
  });

  await t.test('clock rollback and monotonic expiry close the original snapshot', async () => {
    for (const rollback of [false, true]) {
      const f = fixture(tls), adapter = openCorelyDevGatewayCredentialRotation(f.options);
      if (rollback) f.advanceWall(-1); else f.advanceMono(60_000);
      assert.throws(() => adapter.receipt(), denied('GATEWAY_ROTATION_HELD'));
      await assert.rejects(adapter.withLease(leaseAck), denied('GATEWAY_ROTATION_HELD'));
    }
  });
});
