import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { snapshotModelRequest, LOCAL_ORIGINAL50_CORPUS_SHA256 } from './corely-model-contract.mjs';
import { corelyPlanPayload } from './siwc-local-model-port.mjs';

// Structural capability tests only, no private corpus, credentials or network.
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const hash = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const syntheticScope = { tenantId: 'moztech', brandId: 'moztech-test', synthetic: true, jobId: 'local-test-job' };
const historicalScope = { tenantId: 'moztech', brandId: 'moztech-test', dataClass: 'historical_regression',
  corpusSha256: LOCAL_ORIGINAL50_CORPUS_SHA256, jobId: 'local-test-job' };
function request(scope) {
  const content = { version: 1, callId: 'contract-test', workload: 'REPLY_LLM', purpose: 'reply_generation',
    model: 'gpt-6.1-sol', scope, system: 'Synthetic fixture only.', user: 'Synthetic text.', schemaSha256: null };
  return { ...content, inputSha256: hash(content) };
}
test('ordinary ports still admit only the existing exact synthetic scope', () => {
  assert.deepEqual(snapshotModelRequest(request(syntheticScope)).scope, syntheticScope);
  assert.throws(() => snapshotModelRequest(request(historicalScope)), { code: 'SCOPE_NOT_ADMITTED' });
  assert.throws(() => corelyPlanPayload(request(historicalScope), 'info'), { code: 'SCOPE_NOT_ADMITTED' });
});
test('private local regression capability admits only the approved fixed corpus without synthetic promotion', () => {
  const options = { allowHistoricalRegression: true };
  const admitted = snapshotModelRequest(request(historicalScope), options);
  assert.equal(admitted.scope.dataClass, 'historical_regression');
  assert.equal(Object.hasOwn(admitted.scope, 'synthetic'), false);
  for (const scope of [
    { ...historicalScope, corpusSha256: 'a'.repeat(64) },
    { ...historicalScope, synthetic: true }, { ...historicalScope, synthetic: false },
    { ...historicalScope, brandId: 'another-brand' }, { ...historicalScope, tenantId: 'another-tenant' },
    { ...historicalScope, dataClass: 'real_customers' }, { ...historicalScope, extra: true },
  ]) assert.throws(() => snapshotModelRequest(request(scope), options), { code: 'SCOPE_NOT_ADMITTED' });
  const changed = request(historicalScope); changed.scope.jobId = 'different-job';
  assert.throws(() => snapshotModelRequest(changed, options), { code: 'INPUT_MISMATCH' });
});
test('scope opt-in cannot be obtained from inherited properties or accessors', () => {
  for (const options of [true, { allowHistoricalRegression: false }, { allowHistoricalRegression: true, apiFallback: true },
    Object.create({ allowHistoricalRegression: true }), Object.defineProperty({}, 'allowHistoricalRegression',
      { enumerable: true, get() { throw new Error('GETTER_MUST_NOT_RUN'); } })]) {
    assert.throws(() => snapshotModelRequest(request(historicalScope), options), { code: 'INVALID_REQUEST' });
  }
});
