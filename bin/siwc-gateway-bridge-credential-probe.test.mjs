import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:https';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { bridgeLeafSpkiSha256, verifyCorelyDevBridgeCredentialRotation } from './siwc-gateway-bridge-credential-probe.mjs';
import { createSiwcGatewayModelTransports } from './siwc-gateway-model-port.mjs';

test('bridge proof checks real pinned TLS and old-secret rejection before its original expiry, with no provider', async t => {
  // The sealed VM image does not include openssl. Its one-shot diagnostic
  // generates this synthetic CA/keys on the host and mounts only that fixture.
  const prebuilt = process.env.CORELY_SIWC_VM_ISOLATED_TLS_FIXTURE === '1';
  const dir = prebuilt ? '/proof/tls' : await mkdtemp(join(tmpdir(), 'bridge-credential-proof-'));
  if (!prebuilt) t.after(() => rm(dir, { recursive: true, force: true }));
  const openssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' });
  const text = file => readFile(join(dir, file), 'utf8');
  if (!prebuilt) {
    openssl('req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '1', '-keyout', 'ca.key', '-out', 'ca.pem',
      '-subj', '/CN=Synthetic bridge probe CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign');
    await writeFile(join(dir, 'leaf.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:corely-siwc-bridge\n');
  }
  const generation = [];
  for (const i of [1, 2]) {
    const name = `leaf-${i}`;
    if (!prebuilt) {
      openssl('req', '-new', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=corely-siwc-bridge', '-keyout', `${name}.key`, '-out', `${name}.csr`);
      openssl('x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-set_serial', String(i),
        '-days', '1', '-extfile', 'leaf.ext', '-out', `${name}.pem`);
    }
    generation.push({ cert: await text(`${name}.pem`), key: await text(`${name}.key`), secret: `SYNTHETIC_BRIDGE_KEY_${i}_`.repeat(3) });
  }
  const abort = new AbortController(), diagnostics = [];
  t.after(() => abort.abort());
  let providerCalls = 0, relayCalls = 0, requestCount = 0;
  const transport = version => createSiwcGatewayModelTransports({
    sessions: { generate: async () => { providerCalls++; assert.fail('no provider call permitted'); } },
    gatewayUrl: 'https://newapi-dev.corely.cc/v1/responses', gatewayToken: 'SYNTHETIC_RELAY_KEY_'.repeat(3),
    bridgeSecret: version.secret, signal: abort.signal,
    fetchImpl: async () => { relayCalls++; assert.fail('no relay request permitted'); }, onDiagnostic: row => diagnostics.push(row),
  });
  let current = transport(generation[0]);
  const server = createServer(generation[0], (req, res) => { requestCount++; void current.handleRequest(req, res); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(8443, '127.0.0.1', resolve); });
  t.after(() => new Promise(resolve => { current.close(); server.close(resolve); server.closeAllConnections(); }));
  const lookup = (host, options, callback) => {
    assert.equal(host, 'corely-siwc-bridge'); assert.deepEqual(options, { family: 4, all: false });
    callback(null, '127.0.0.1', 4);
  };
  const [old, next] = generation;
  const now = Date.now(), options = { enabled: true, signal: abort.signal, lookup, bridgeCaPem: await text('ca.pem'),
    predecessorLeafSpkiSha256: bridgeLeafSpkiSha256(old.cert), successorLeafSpkiSha256: bridgeLeafSpkiSha256(next.cert),
    predecessorSecret: old.secret, successorSecret: next.secret, predecessorExpiresAt: now + 60_000, successorExpiresAt: now + 90_000 };
  const denied = error => error.code === 'GATEWAY_BRIDGE_PROOF_HELD' && error.cause === undefined;
  // An old listener or a public DNS answer cannot see either bearer.
  await assert.rejects(verifyCorelyDevBridgeCredentialRotation(options), denied);
  await assert.rejects(verifyCorelyDevBridgeCredentialRotation({ ...options, lookup: (_h, _o, cb) => cb(null, '8.8.8.8', 4) }), denied);
  assert.equal(requestCount, 0);
  // Positive old-generation baseline: the same exact old secret reaches nonce
  // validation before the swap; next secret is rejected before reading a body.
  await verifyCorelyDevBridgeCredentialRotation({ ...options,
    predecessorLeafSpkiSha256: options.successorLeafSpkiSha256, successorLeafSpkiSha256: options.predecessorLeafSpkiSha256,
    predecessorSecret: next.secret, successorSecret: old.secret });
  assert.equal(requestCount, 2);
  assert.deepEqual(diagnostics.splice(0), [
    { stage: 'BRIDGE_INVOCATION', reason: 'GATEWAY_NONCE_INVALID', httpStatus: 409, consumed: false },
    { stage: 'BRIDGE_ADMISSION', reason: 'GATEWAY_REQUEST_REJECTED', httpStatus: 403, consumed: false },
  ]);
  current.close(); current = transport(next); server.setSecureContext(next);
  assert.deepEqual(await verifyCorelyDevBridgeCredentialRotation(options), {
    status: 'CORELY_DEV_BRIDGE_CREDENTIAL_ROTATION_VERIFIED', successorTlsPinned: true,
    successorCredentialStatus: 409, predecessorCredentialStatus: 403, predecessorStillUnexpired: true, modelDispatchRequested: false,
  });
  assert.deepEqual(diagnostics, [
    { stage: 'BRIDGE_INVOCATION', reason: 'GATEWAY_NONCE_INVALID', httpStatus: 409, consumed: false },
    { stage: 'BRIDGE_ADMISSION', reason: 'GATEWAY_REQUEST_REJECTED', httpStatus: 403, consumed: false },
  ]);
  await assert.rejects(verifyCorelyDevBridgeCredentialRotation({ ...options, predecessorExpiresAt: now }), denied);
  assert.equal(requestCount, 4); assert.equal(providerCalls, 0); assert.equal(relayCalls, 0);
});
