import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { openCorelyDevGoTokenInstaller as open } from './siwc-gateway-go-token-installer.mjs';

const START = 1_800_000_000_000, MODEL = 'gpt-6.1-sol', GROUP = 'corely-siwc-fixture';
const parent = { authorityIdSha256: 'a'.repeat(64), expiresAt: START + 2_000_000, ownerId: 9, channelId: 71, group: GROUP, allowedIp: '192.0.2.10' };
const pat = 'nap_' + 'Z'.repeat(42) + 'z', previousToken = 'P'.repeat(48);
const label = gen => `corely-siwc-${parent.authorityIdSha256.slice(0, 18)}-${gen}`;
const good = (data) => ({ success: true, message: '', ...(data === undefined ? {} : { data }) });
const expectedHold = error => error.code === 'GO_TOKEN_INSTALL_HELD' && error.message === error.code;
const masked = key => `${key.slice(0, 4)}**********${key.slice(-4)}`;
const wire = (id, name, expiry, key) => ({
  id, name, key: masked(key), user_id: parent.ownerId, status: 1, expired_time: expiry / 1000, model_limits_enabled: true, model_limits: MODEL,
  group: GROUP, allow_ips: parent.allowedIp, cross_group_retry: false, auto_groups: null, unlimited_quota: false, remain_quota: 1, allow_user_quota_query: false,
});

async function fixture(t, overrides = {}) {
  const dir = await mkdtemp(join(await realpath(tmpdir()), 'go-token-synthetic-'));
  t.after(() => rm(dir, { force: true, recursive: true }));
  const controller = new AbortController(), calls = [], rows = new Map(), remote = { afterDelete: false, lost: false, time: START };
  const oldExpiry = START + 600_000;
  rows.set(10, { row: wire(10, label(1), oldExpiry, previousToken), token: previousToken });
  const options = { enabled: true, stateDir: dir, authority: parent, management: { token: pat, expiresAt: parent.expiresAt }, signal: controller.signal,
    now: () => remote.time,
    verifyRoute: async () => ({ authorityIdSha256: parent.authorityIdSha256, ownerId: parent.ownerId, channelId: parent.channelId,
      allowedIp: parent.allowedIp, group: GROUP, model: MODEL, revisionSha256: 'b'.repeat(64), verifiedAt: remote.time,
      ordinaryOwner: true, sameOwnerAcrossTokenIds: true, apiFallbackEnabled: false, paidCreditsEnabled: false, groupRatio: 0,
      bodyPassthrough: true, headerPassthrough: false, retryCount: 0, ...overrides.route }),
    async fetchImpl(url, init) {
      const target = new URL(url); assert.equal(target.origin, 'https://newapi-dev.corely.cc');
      assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit'); assert.equal(init.cache, 'no-store');
      assert.equal(init.headers['Accept-Language'], 'en'); assert.equal(init.signal.aborted, false);
      const path = target.pathname, method = init.method, bearer = init.headers.Authorization;
      calls.push([method, path]);
      const requestId = `synthetic-probe-${calls.length}`;
      const json = (body, status = 200) => new Response(JSON.stringify(body), { status,
        headers: { 'content-type': 'application/json; charset=utf-8', 'x-oneapi-request-id': requestId } });
      if (path === '/v1/models') {
        assert.equal(method, 'GET'); assert.equal(init.headers['New-Api-User'], undefined);
        const found = Array.from(rows.values()).some(row => bearer === `Bearer sk-${row.token}`);
        return found || remote.afterDelete && overrides.staleOld && bearer === `Bearer sk-${previousToken}`
          ? json({ success: true, object: 'list', data: [{ id: MODEL }] })
          : json({ error: { type: 'new_api_error', code: '', message: `Invalid token (request id: ${overrides.badDenial ? 'wrong-id' : requestId})` } }, 401);
      }
      assert.equal(bearer, `Bearer ${pat}`); assert.equal(init.headers['New-Api-User'], String(parent.ownerId));
      if (path === '/api/user/self') {
        assert.equal(method, 'GET');
        return json(good({ id: parent.ownerId, role: overrides.role ?? 1, status: 1, group: GROUP }));
      }
      if (path === '/api/token/search') {
        assert.equal(method, 'GET'); assert.equal(target.searchParams.get('page_size'), '10');
        const items = [...rows.values()].filter(entry => entry.row.name === target.searchParams.get('keyword')).map(entry => entry.row);
        return json(good({ items, total: items.length }));
      }
      if (path === '/api/token/' && method === 'POST') {
        const body = JSON.parse(init.body), id = Math.max(...rows.keys()) + 1, key = String(id).repeat(24);
        assert.equal(body.name, label(id - 9)); assert.equal(body.group, GROUP); assert.equal(body.model_limits, MODEL);
        assert.equal(body.allow_ips, parent.allowedIp); assert.equal(body.cross_group_retry, false); assert.equal(body.remain_quota, 1);
        assert.equal(body.unlimited_quota || body.allow_user_quota_query, false);
        rows.set(id, { row: wire(id, body.name, body.expired_time * 1000, key), token: key });
        if (overrides.lostCreate) { remote.lost = true; throw new Error('synthetic lost response'); }
        return json(good());
      }
      const [id, key] = path.replace('/api/token/', '').split('/');
      const row = rows.get(Number(id));
      assert.ok(row);
      if (method === 'DELETE') { rows.delete(Number(id)); remote.afterDelete = true; return json(good()); }
      if (method === 'POST' && key === 'key') return json(good({ key: row.token }));
      assert.equal(method, 'GET'); return json(good(row.row));
    },
  };
  const input = { generation: 1, previousTokenId: 10, previousToken, previousExpiresAt: oldExpiry,
    nextExpiresAt: START + 900_000, signal: controller.signal };
  return { dir, input, options, calls, remote, rows };
}

test('two exact generations, fixed scoped bearer, actual retirement and secret-free journal across reopen', async t => {
  const f = await fixture(t), first = await open(f.options);
  const result = await first.rotate(f.input); first.close();
  assert.deepEqual(result.receipt, { status: 'CORELY_DEV_GO_TOKEN_REPLACEMENT_VERIFIED', generation: 2, tokenId: 11,
    expiresAt: f.input.nextExpiresAt, predecessorRejected: true, routeRevisionSha256: 'b'.repeat(64), modelRequestsMade: 0 });
  const expected = [['GET', '/api/user/self'], ['GET', '/api/token/10'], ['POST', '/api/token/10/key'], ['GET', '/v1/models'],
    ['GET', '/api/token/search'], ['POST', '/api/token/'], ['GET', '/api/token/search'], ['POST', '/api/token/11/key'],
    ['GET', '/v1/models'], ['GET', '/api/user/self'], ['DELETE', '/api/token/10'], ['GET', '/v1/models'], ['GET', '/v1/models']];
  assert.deepEqual(f.calls, expected);
  const reopened = await open(f.options);
  const next = await reopened.rotate({ ...f.input, generation: 2, previousTokenId: 11, previousToken: result.token,
    previousExpiresAt: result.receipt.expiresAt, nextExpiresAt: START + 1_200_000 });
  assert.equal(next.receipt.generation, 3);
  reopened.close();
  const files = await readdir(f.dir); assert.equal(files.length, 4);
  for (const file of files) {
    const data = await readFile(join(f.dir, file), 'utf8');
    assert.ok(![pat, previousToken, result.token, next.token].some(raw => data.includes(raw)));
  }
});

test('lost mutation or stale-cache success never records a commit or repeats POST after restart', async t => {
  for (const scenario of [{ lostCreate: true }, { staleOld: true }, { badDenial: true }]) {
    const f = await fixture(t, scenario), first = await open(f.options);
    await assert.rejects(first.rotate(f.input), expectedHold);
    assert.deepEqual(await readdir(f.dir), [`${label(2)}.intent.json`]);
    const second = await open(f.options);
    await assert.rejects(second.rotate(f.input), expectedHold);
    assert.equal(f.calls.filter(([method, path]) => method === 'POST' && path === '/api/token/').length, 1);
    assert.equal(f.calls.filter(([method]) => method === 'DELETE').length, scenario.lostCreate ? 0 : 1);
  }
});

test('disabled, root owner, affinity drift and wrong old bearer stop before any Go mutation', async t => {
  await assert.rejects(open({ get stateDir() { assert.fail('disabled opened state'); } }), { code: 'GO_TOKEN_INSTALL_DISABLED' });
  for (const scenario of [{ role: 100 }, { route: { sameOwnerAcrossTokenIds: false } }, { wrongOld: true }]) {
    const f = await fixture(t, scenario);
    const installer = await open(f.options);
    await assert.rejects(installer.rotate({ ...f.input, ...(scenario.wrongOld ? { previousToken: 'PPPP' + 'X'.repeat(40) + 'PPPP' } : {}) }), expectedHold);
    assert.ok(!f.calls.some(([method, path]) => method === 'DELETE' || method === 'POST' && path === '/api/token/'));
    assert.deepEqual(await readdir(f.dir), []);
  }
});

test('two simultaneous installer owners share one durable generation CAS', async t => {
  const f = await fixture(t);
  const [a, b] = await Promise.all([open(f.options), open(f.options)]);
  const replies = await Promise.allSettled([a.rotate(f.input), b.rotate(f.input)]);
  assert.equal(replies.filter(reply => reply.status === 'fulfilled').length, 1);
  assert.equal(replies.filter(reply => reply.status === 'rejected' && expectedHold(reply.reason)).length, 1);
  assert.equal(f.calls.filter(([method, path]) => method === 'POST' && path === '/api/token/').length, 1);
  a.close(); b.close();
});
