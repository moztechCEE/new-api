import assert from 'node:assert/strict';
import { test } from 'node:test';
import { openCorelyDevGoTokenLoopback as open } from './siwc-gateway-go-loopback.mjs';

const BASE = 'https://newapi-dev.corely.cc', PRIVATE = 'http://127.0.0.1:3000', authorityIdSha256 = 'a'.repeat(64);
const metadata = { enabled: true, authorityIdSha256, ownerId: 8, allowedIp: '127.0.0.1' };
const held = { code: 'GO_TOKEN_LOOPBACK_HELD' };
const init = { method: 'GET', headers: { Accept: 'application/json', 'Accept-Language': 'en', 'Accept-Encoding': 'identity',
  'Cache-Control': 'no-cache, no-store', Pragma: 'no-cache', Authorization: 'Bearer sk-' + 'A'.repeat(48) },
body: undefined, cache: 'no-store', credentials: 'omit', redirect: 'error', signal: new AbortController().signal };
const response = (url, extras = {}) => ({ url, status: 200, headers: new Headers(), body: new Response('{}').body, ...extras });

test('disabled reads no caller options; fixed authenticated probe is mapped to the numeric VM endpoint', async () => {
  assert.throws(() => open({ get requestImpl() { assert.fail('disabled'); } }), { code: 'GO_TOKEN_LOOPBACK_DISABLED' });
  const fetch = open({ ...metadata, requestImpl: async (url, req) => {
    assert.equal(url, PRIVATE + '/v1/models');
    assert.deepEqual(Object.keys(req).sort(), ['body', 'headers', 'method', 'signal']);
    assert.equal(req.headers.Host, undefined); assert.equal(req.method, 'GET'); assert.equal(req.body, undefined);
    return response(url);
  } });
  const reply = await fetch(BASE + '/v1/models', init);
  assert.equal(reply.url, BASE + '/v1/models'); assert.equal(reply.status, 200); assert.equal(reply.redirected, false);
});

test('no network request on egress, model generation, method/path/query alias, Host or proxy headers', async () => {
  const fetch = open({ ...metadata, requestImpl: () => assert.fail('a rejected request reached HTTP') });
  for (const [url, request] of [
    ['https://example.test/v1/models', init], [BASE + '/v1/responses', { ...init, method: 'POST' }],
    [BASE + '/v1/models', { ...init, method: 'POST' }], [BASE + '/v1/models?key=anything', init],
    [BASE + '/%2ev1/models', init], [BASE + '//example.test/v1/models', init],
    [BASE + '/v1/models', { ...init, headers: { ...init.headers, Host: 'example.test' } }],
    [BASE + '/v1/models', { ...init, headers: { ...init.headers, 'x-forwarded-host': 'example.test' } }],
    [BASE + '/v1/models', { ...init, headers: { ...init.headers, 'Proxy-Authorization': 'unused' } }],
    [BASE + '/v1/models', { ...init, redirect: 'follow' }],
  ]) await assert.rejects(fetch(url, request), held);
});

test('foreign raw URL, redirects and Location are not normalized into a logical success', async () => {
  for (const extras of [{ url: BASE + '/v1/models' }, { status: 302 }, { redirected: true }, { headers: new Headers({ location: 'https://example.test/' }) }]) {
    const fetch = open({ ...metadata, requestImpl: async url => response(url, extras) });
    await assert.rejects(fetch(BASE + '/v1/models', init), held);
  }
});
