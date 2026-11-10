// No-provider bridge verification. This is deliberately not a relay request:
// a fixed malformed nonce, no model or input, and no pending lease to consume.
import { createHash, X509Certificate } from 'node:crypto';
import { lookup as resolveIp } from 'node:dns';
import { request } from 'node:https';
import { isIP } from 'node:net';
import { checkServerIdentity } from 'node:tls';

const HOST = 'corely-siwc-bridge', PORT = 8443;
const PROBE = '{"metadata":{"corely_siwc_nonce":"invalid"}}';
const SHA = /^[a-f0-9]{64}$/u;
const SECRET = /^[A-Za-z0-9_-]{43,256}$/u;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const hold = () => Object.assign(new Error('GATEWAY_BRIDGE_PROOF_HELD'), { code: 'GATEWAY_BRIDGE_PROOF_HELD' });
const disabled = () => Object.assign(new Error('GATEWAY_BRIDGE_PROOF_DISABLED'), { code: 'GATEWAY_BRIDGE_PROOF_DISABLED' });
const response = (code) => JSON.stringify({ error: { type: 'corely_siwc_error', code, message: 'Corely SIWC request held' } });
function privateV4(ip) {
  if (isIP(ip) !== 4) return false;
  const [a, b] = ip.split('.').map(Number);
  return a === 127 || a === 10 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168;
}
function parsedCertificate(pem) {
  if (typeof pem !== 'string' || pem.length > 16_384) throw hold();
  const cert = new X509Certificate(pem);
  if (cert.toString().trim() !== pem.trim()) throw hold();
  return cert;
}
export function bridgeLeafSpkiSha256(pem) {
  try { return digest(parsedCertificate(pem).publicKey.export({ type: 'spki', format: 'der' })); }
  catch { throw hold(); }
}

/** Verify the same successor TLS listener with both credentials. Never
 * follow redirects or output secrets, bodies, connection addresses or errors. */
export async function verifyCorelyDevBridgeCredentialRotation(options = {}) {
  if (options.enabled !== true) throw disabled();
  try {
    const { bridgeCaPem, predecessorLeafSpkiSha256, successorLeafSpkiSha256, predecessorSecret, successorSecret,
      predecessorExpiresAt, successorExpiresAt, signal, lookup = resolveIp, now = Date.now } = options;
    const start = now(), deadline = Math.min(predecessorExpiresAt, successorExpiresAt);
    if (!(signal instanceof AbortSignal) || signal.aborted || typeof lookup !== 'function' || !Number.isSafeInteger(start) ||
        !Number.isSafeInteger(predecessorExpiresAt) || !Number.isSafeInteger(successorExpiresAt) || deadline - start < 2000 ||
        typeof predecessorLeafSpkiSha256 !== 'string' || !SHA.test(predecessorLeafSpkiSha256) ||
        typeof successorLeafSpkiSha256 !== 'string' || !SHA.test(successorLeafSpkiSha256) ||
        predecessorLeafSpkiSha256 === successorLeafSpkiSha256 || typeof predecessorSecret !== 'string' ||
        !SECRET.test(predecessorSecret) || typeof successorSecret !== 'string' || !SECRET.test(successorSecret) ||
        predecessorSecret === successorSecret || !parsedCertificate(bridgeCaPem).ca) throw hold();
    const active = AbortSignal.any([signal, AbortSignal.timeout(Math.min(12_000, deadline - start))]);
    let pinnedAddress;
    const safeLookup = (hostname, _options, callback) => {
      if (hostname !== HOST) { callback(hold()); return; }
      lookup(HOST, { family: 4, all: false }, (error, ip, family) => {
        if (active.aborted || error || family !== 4 || !privateV4(ip) || pinnedAddress && pinnedAddress !== ip) { callback(hold()); return; }
        pinnedAddress = ip; callback(null, ip, 4);
      });
    };
    const single = (secret, expectedStatus, expectedCode) => new Promise((resolve, reject) => {
      let peerVerified = false;
      const req = request({
        protocol: 'https:', hostname: HOST, port: PORT, servername: HOST, path: '/v1/responses', method: 'POST',
        agent: false, autoSelectFamily: false, family: 4, ca: bridgeCaPem, rejectUnauthorized: true, minVersion: 'TLSv1.2',
        lookup: safeLookup, signal: active, maxHeaderSize: 4096, headers: {
          authorization: `Bearer ${secret}`, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(PROBE)),
        },
        checkServerIdentity(name, peer) {
          try {
            if (name !== HOST || checkServerIdentity(HOST, peer) || !Buffer.isBuffer(peer.raw)) return hold();
            const leaf = new X509Certificate(peer.raw);
            if (leaf.ca || leaf.checkHost(HOST, { subject: 'never', wildcards: false }) !== HOST ||
                digest(leaf.publicKey.export({ type: 'spki', format: 'der' })) !== successorLeafSpkiSha256) return hold();
            peerVerified = true;
          } catch { return hold(); }
          return undefined;
        },
      }, res => {
        // Node can detach a Connection: close socket before the response EOF.
        // Bind the actual authenticated peer when response headers arrive.
        const receivedFromPinnedPeer = Boolean(peerVerified && pinnedAddress && res.socket?.remoteAddress === pinnedAddress);
        let size = 0;
        const chunks = [];
        res.on('error', () => reject(hold()));
        res.on('aborted', () => reject(hold()));
        res.on('data', chunk => {
          size += chunk.length;
          if (size > 512) res.destroy(hold()); else chunks.push(chunk);
        });
        res.on('end', () => {
          if (!receivedFromPinnedPeer || active.aborted || res.statusCode !== expectedStatus || res.headers.location !== undefined ||
              res.headers['content-type'] !== 'application/json; charset=utf-8' || res.headers['cache-control'] !== 'no-store' ||
              !Buffer.concat(chunks).equals(Buffer.from(response(expectedCode)))) { reject(hold()); return; }
          resolve();
        });
      });
      req.on('error', () => reject(hold()));
      req.end(PROBE);
    });
    await single(successorSecret, 409, 'bridge_request_held');
    await single(predecessorSecret, 403, 'bridge_request_rejected');
    const observed = now();
    if (active.aborted || !Number.isSafeInteger(observed) || observed < start || observed >= deadline) throw hold();
    return Object.freeze({ status: 'CORELY_DEV_BRIDGE_CREDENTIAL_ROTATION_VERIFIED', successorTlsPinned: true,
      successorCredentialStatus: 409, predecessorCredentialStatus: 403, predecessorStillUnexpired: true, modelDispatchRequested: false });
  } catch { throw hold(); }
}
