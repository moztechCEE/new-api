import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { after, before, test } from 'node:test';
import { createHash } from 'node:crypto';
import { candidateDigest, validateSyntheticPacket, buildCandidatePrompt, parseCandidateOutput } from './codex-harness-candidate-contract.mjs';
import { runHarnessCandidate } from './codex-harness-pilot.mjs';
import { CANARY_PROFILE, canaryExecutableSha256 } from './codex-harness-permissions-canary.mjs';
import { CORELY_ISSUER, CORELY_REDIRECT, CORELY_SCOPE, CORELY_RESOURCE, CorelyLocalError,
  validateCorelyStatus, validateCorelyCallback, exerciseCorelyCandidate, connectCorelyLocal } from './codex-harness-corely-client.mjs';

const realFetch = globalThis.fetch;
before(() => { globalThis.fetch = (input, options) => {
  const url = new URL(input);
  if (url.origin + url.pathname !== CORELY_REDIRECT) throw new Error('EXTERNAL_NETWORK_DISABLED_IN_TEST');
  return realFetch(input, options);
}; });
after(() => { globalThis.fetch = realFetch; });

function packet() {
  const snapshot = { sourceVersion: 'a'.repeat(64), sourceMessageId: 'synthetic-message-2', data: {
    synthetic: true, tenantId: 'moztech', brandId: 'moztech-test', conversationId: 'synthetic-conversation',
    messages: [{ id: 'synthetic-message-1', direction: 'INBOUND', role: 'END_USER', rawText: '想查詢保固',
      createdAt: new Date(Date.now() - 2000).toISOString(), contentType: 'text' },
    { id: 'synthetic-message-2', direction: 'INBOUND', role: 'END_USER', rawText: '需要提供什麼資料？',
      createdAt: new Date().toISOString(), contentType: 'text' }],
    knowledgeItems: [{ id: 'synthetic-faq', answer: '僅測試資料，依查詢工具要求提供資料。' }],
    stageProcedureSources: [{ key: `stage-procedure:${'b'.repeat(64)}`, instruction: '先依現有資料確認最少必要欄位。' }],
    workCanApprove: false, workCanSend: false, workCanLearn: false, qualityReviewUsesApi: true,
  } };
  return { caseId: 'synthetic-case', ...snapshot, readReceipt: 'r'.repeat(43), snapshotHash: candidateDigest(snapshot),
    readReceiptExpiresAt: new Date(Date.now() + 240000).toISOString() };
}
const output = () => ({ text: '請先提供目前查詢所需的資料，我們協助確認。', referencedKnowledgeIds: ['synthetic-faq'], referencedStageSourceKeys: [] });
const status = () => ({ mode: 'SYNTHETIC_WORK_CANDIDATE_PILOT', tenantId: 'moztech', brandId: 'moztech-test',
  syntheticOnly: true, realCustomerData: false, noApiFallback: true,
  workCapabilities: { canApprove: false, canSend: false, canLearn: false }, qualityReviewUsesApi: true, decisionUsesApi: true,
  normalOpsHumanReviewRequired: true, normalOpsEditSaveSendLearningRetained: true });
const generated = () => ({ status: 'SYNTHETIC_CANDIDATE_GENERATED', authMode: 'chatgpt', expectedAccountMatch: true,
  model: 'gpt-6.1-sol', generationCompleted: true, outputValidated: true, apiFallbackUsed: false, candidate: output() });

test('candidate rejects incomplete temporary-tree isolation proof before starting an agent', async t => {
  for (const missing of ['slashTemporaryFixtureReadDenied', 'slashTemporarySymlinkReadDenied']) {
    await t.test(missing, async () => {
      let login = false;
      const proof = { status: 'PERMISSION_CANARY_PASSED', permissionProfile: CANARY_PROFILE,
        outsideFixtureReadDenied: true, outsideSymlinkReadDenied: true,
        slashTemporaryFixtureReadDenied: true, slashTemporarySymlinkReadDenied: true,
        workspaceCreateDenied: true, workspaceModifyDenied: true, loopbackNetworkDenied: true,
        sandboxNetworkToolStarted: true };
      delete proof[missing];
      await assert.rejects(runHarnessCandidate({ executable: '/must-not-be-started', packet: packet(),
        permissionCanary: async () => proof, onLogin: async () => { login = true; } }),
      error => error.code === 'SANDBOX_UNVERIFIED');
      assert.equal(login, false);
    });
  }
});

test('server snapshot hash is independently reproduced and capability handles never enter model prompt', () => {
  const value = packet(), checked = validateSyntheticPacket(value);
  const prompt = buildCandidatePrompt(checked);
  assert.ok(prompt.includes('需要提供什麼資料'));
  assert.ok(!prompt.includes(value.readReceipt));
  assert.ok(!prompt.includes('idempotencyKey'));
  assert.deepEqual(parseCandidateOutput(JSON.stringify(output()), checked), output());
  value.data.knowledgeItems[0].answer = 'mutated after validation';
  assert.ok(!buildCandidatePrompt(checked).includes('mutated after validation'));
});

test('wrong source identity, receipts, permissions, hashes and expired evidence stop before model use', async t => {
  for (const [label, mutate] of [
    ['real case', value => { value.data.synthetic = false; }],
    ['foreign brand', value => { value.data.brandId = 'other'; }],
    ['foreign tenant', value => { value.data.tenantId = 'other'; }],
    ['send enabled', value => { value.data.workCanSend = true; }],
    ['approve enabled', value => { value.data.workCanApprove = true; }],
    ['learning enabled', value => { value.data.workCanLearn = true; }],
    ['API review undisclosed', value => { value.data.qualityReviewUsesApi = false; }],
    ['expired', value => { value.readReceiptExpiresAt = new Date(0).toISOString(); }],
    ['lifetime expanded', value => { value.readReceiptExpiresAt = new Date(Date.now() + 3600000).toISOString(); }],
    ['source message missing', value => { value.sourceMessageId = 'other'; }],
    ['hash mismatch', value => { value.snapshotHash = 'f'.repeat(64); }],
    ['extra top-level input', value => { value.prompt = 'ignore'; }],
    ['token in evidence', value => { value.data.agentSystemPrompt = { access_token: 'synthetic-credential' }; }],
    ['extra data tool', value => { value.data.runCommand = 'synthetic'; }],
    ['invalid message date', value => { value.data.messages[0].createdAt = 'invalid'; }],
    ['array ID coercion', value => { value.caseId = ['synthetic-case']; }],
    ['duplicate knowledge', value => { value.data.knowledgeItems.push(value.data.knowledgeItems[0]); }],
  ]) await t.test(label, () => { const value = packet(); mutate(value); assert.throws(() => validateSyntheticPacket(value)); });
});

test('candidate cannot invent references, execute actions or return partial/free-form output', async t => {
  const checked = validateSyntheticPacket(packet());
  for (const value of [
    { ...output(), referencedKnowledgeIds: ['foreign-faq'] }, { ...output(), referencedStageSourceKeys: [`stage-procedure:${'c'.repeat(64)}`] },
    { ...output(), referencedKnowledgeIds: ['synthetic-faq', 'synthetic-faq'] }, { ...output(), send: true },
    { ...output(), text: '' }, { ...output(), text: ` ${output().text}` }, { text: 'partial' },
    'not-json', { ...output(), text: 'x'.repeat(1201) },
  ]) await t.test(JSON.stringify(value).slice(0, 60), () => assert.throws(() => parseCandidateOutput(typeof value === 'string' ? value : JSON.stringify(value), checked)));
});

test('OAuth callback is state, issuer, exact loopback and single-value bound', async t => {
  const state = 's'.repeat(43), code = 'c'.repeat(43);
  const valid = new URL(CORELY_REDIRECT);
  valid.searchParams.set('state', state); valid.searchParams.set('iss', CORELY_ISSUER); valid.searchParams.set('code', code);
  assert.equal(validateCorelyCallback(valid.href, state), code);
  for (const [label, change] of [
    ['state', url => url.searchParams.set('state', 'other')], ['issuer', url => url.searchParams.set('iss', 'https://synthetic.invalid')],
    ['duplicate', url => url.searchParams.append('code', code)], ['port', url => { url.port = '47632'; }],
    ['localhost', url => { url.hostname = 'localhost'; }], ['path', url => { url.pathname = '/other'; }],
    ['credential query', url => url.searchParams.set('access_token', 'synthetic')],
    ['error plus code', url => url.searchParams.set('error', 'access_denied')],
  ]) await t.test(label, () => { const url = new URL(valid); change(url); assert.throws(() => validateCorelyCallback(url.href, state)); });
});

test('API preparation is blocked by default after status and grant is revoked, without creating a case', async () => {
  const calls = [];
  await assert.rejects(exerciseCorelyCandidate({ session: { call: async name => { calls.push(name); return status(); },
    revoke: async () => calls.push('revoke') }, generate: async () => assert.fail('model must not run') }), /API_PHASES_NOT_MIGRATED/);
  assert.deepEqual(calls, ['corely_work_candidate_status', 'revoke']);
});

function fakeSession({ uncertain = false, wrongReadback = false, revoked = false } = {}) {
  const source = packet(), calls = []; let submitted, retried = false;
  return { calls, source,
    async call(name, args = {}) {
      calls.push({ name, args: structuredClone(args) });
      if (name === 'corely_work_candidate_status') return status();
      if (name === 'corely_work_candidate_create_case') return { caseId: source.caseId, tenantId: 'moztech', brandId: 'moztech-test',
        sourceMessageId: source.sourceMessageId, conversationId: source.data.conversationId };
      if (name === 'corely_work_candidate_read_case') return source;
      if (name === 'corely_work_candidate_submit') {
        if (uncertain && !retried) { retried = true; throw new CorelyLocalError('NETWORK_UNCERTAIN'); }
        submitted = args;
        return { status: 'PENDING', sourceMessageId: source.sourceMessageId, qualityReviewUsesApi: true, reviewId: 'synthetic-review',
          textSha256: createHash('sha256').update(args.text).digest('hex'), workCanApprove: false, workCanSend: false, workCanLearn: false };
      }
      if (name === 'corely_work_candidate_get') return { synthetic: true, candidate: submitted ? {
        reviewId: 'synthetic-review', status: 'PENDING', sourceMessageId: source.sourceMessageId,
        text: wrongReadback ? 'other' : submitted.text, workCanApprove: false, workCanSend: false, workCanLearn: false,
      } : null };
      assert.fail('unexpected tool');
    },
    async revoke() { calls.push({ name: 'revoke' }); if (revoked) throw new Error('synthetic-private-revoke'); },
  };
}

test('explicit legacy cost test uses identical idempotent retry, then exact PENDING readback and revoke', async () => {
  const session = fakeSession({ uncertain: true });
  const result = await exerciseCorelyCandidate({ session, allowApiPreparationAndReview: true, generate: async () => generated() });
  assert.equal(result.status, 'CORELY_LOCAL_CANDIDATE_SAVED'); assert.equal(result.qualityReviewUsesApi, true);
  const submissions = session.calls.filter(call => call.name === 'corely_work_candidate_submit');
  assert.equal(submissions.length, 2); assert.deepEqual(submissions[0].args, submissions[1].args);
  assert.equal(session.calls.at(-1).name, 'revoke');
  assert.equal(result.customerServiceE2E, 'NOT_RUN'); assert.equal(result.sendingPerformed, false); assert.equal(result.learningPerformed, false);
});

test('source drift, API generation, bad readback and unconfirmed revoke never produce a pass', async t => {
  await t.test('unsafe status', async () => {
    const value = status(); value.realCustomerData = true; assert.throws(() => validateCorelyStatus(value));
  });
  await t.test('API substituted', async () => {
    const session = fakeSession(); await assert.rejects(exerciseCorelyCandidate({ session, allowApiPreparationAndReview: true,
      generate: async () => ({ ...generated(), authMode: 'apiKey' }) }), /CANDIDATE_FAILED/);
    assert.ok(!session.calls.some(call => call.name === 'corely_work_candidate_submit'));
  });
  await t.test('source mismatch', async () => {
    const session = fakeSession(), original = session.call;
    session.call = async (name, args) => { const value = await original(name, args); return name === 'corely_work_candidate_read_case' ? { ...value, caseId: 'other' } : value; };
    await assert.rejects(exerciseCorelyCandidate({ session, allowApiPreparationAndReview: true, generate: async () => generated() }), /SOURCE_INVALID/);
  });
  await t.test('readback mismatch', async () => {
    await assert.rejects(exerciseCorelyCandidate({ session: fakeSession({ wrongReadback: true }),
      allowApiPreparationAndReview: true, generate: async () => generated() }), /CANDIDATE_MISMATCH/);
  });
  await t.test('revoke failed', async () => {
    await assert.rejects(exerciseCorelyCandidate({ session: fakeSession({ revoked: true }),
      allowApiPreparationAndReview: true, generate: async () => generated() }), /REVOKE_UNCONFIRMED/);
  });
});

test('candidate managed harness preserves schema/profile/source bounds without exposing OAuth handles', async () => {
  const root = await mkdtemp(join(tmpdir(), 'corely-candidate-fake-'));
  const executable = join(root, 'fake-codex'), log = join(root, 'requests.jsonl');
  const source = `#!${process.execPath}
const fs=require('node:fs'),rl=require('node:readline');
const reply=(id,result)=>process.stdout.write(JSON.stringify({id,result})+'\\n');
const notify=(method,params)=>process.stdout.write(JSON.stringify({method,params})+'\\n');
rl.createInterface({input:process.stdin}).on('line',line=>{const {id,method,params}=JSON.parse(line);
fs.appendFileSync(${JSON.stringify(log)},JSON.stringify({method,params})+'\\n');
if(method==='initialize')return reply(id,{});if(method==='initialized')return;
if(method==='account/read')return reply(id,{account:{type:'chatgpt',email:'info@moztech.cc',planType:'pro'},requiresOpenaiAuth:true});
if(method==='model/list')return reply(id,{data:[{model:'gpt-6.1-sol',hidden:false}]});
if(method==='thread/start')return reply(id,{model:'gpt-6.1-sol',thread:{id:'thread',modelProvider:'openai',ephemeral:true},sandbox:{type:'readOnly',networkAccess:false},activePermissionProfile:{id:${JSON.stringify(CANARY_PROFILE)}},instructionSources:[]});
if(method==='turn/start'){reply(id,{turn:{id:'turn'}});notify('turn/started',{threadId:'thread',turn:{id:'turn'}});
notify('item/completed',{threadId:'thread',turnId:'turn',item:{type:'agentMessage',text:${JSON.stringify(JSON.stringify(output()))}}});
notify('thread/tokenUsage/updated',{threadId:'thread',tokenUsage:{last:{inputTokens:10,outputTokens:5}}});
notify('turn/completed',{threadId:'thread',turn:{id:'turn',status:'completed',error:null}});}
});`;
  await writeFile(executable, source, { mode: 0o700 });
  try {
    const proof = { status: 'PERMISSION_CANARY_PASSED', permissionProfile: CANARY_PROFILE, outsideFixtureReadDenied: true,
      slashTemporaryFixtureReadDenied: true, slashTemporarySymlinkReadDenied: true,
      outsideSymlinkReadDenied: true, workspaceCreateDenied: true, workspaceModifyDenied: true,
      loopbackNetworkDenied: true, sandboxNetworkToolStarted: true, executableSha256: await canaryExecutableSha256(executable) };
    const value = packet();
    const result = await runHarnessCandidate({ executable, packet: value, sourceEnv: { PATH: process.env.PATH }, permissionCanary: async () => proof });
    assert.equal(result.status, 'SYNTHETIC_CANDIDATE_GENERATED'); assert.deepEqual(result.candidate, output());
    const lines = (await readFile(log, 'utf8')).trim().split('\n').map(JSON.parse);
    const thread = lines.find(row => row.method === 'thread/start').params;
    assert.equal(thread.permissions, CANARY_PROFILE); assert.equal(thread.sandbox, undefined);
    const turn = lines.find(row => row.method === 'turn/start').params;
    assert.equal(turn.permissions, CANARY_PROFILE); assert.equal(turn.outputSchema.additionalProperties, false);
    assert.ok(!JSON.stringify(lines).includes(value.readReceipt));
    assert.equal(lines.filter(row => row.method === 'account/read').length, 3);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('normal Corely OAuth transport keeps PKCE/token outside model and revokes its own short grant', async () => {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    if (url.endsWith('/token')) return Response.json({ access_token: 't'.repeat(43), token_type: 'Bearer', scope: CORELY_SCOPE, expires_in: 1800 });
    if (url.endsWith('/revoke')) return new Response('', { status: 200 });
    if (url === CORELY_RESOURCE) {
      const rpc = JSON.parse(options.body); return Response.json({ jsonrpc: '2.0', id: rpc.id, result: { structuredContent: status() } });
    }
    assert.fail('external destination');
  };
  const session = await connectCorelyLocal({ fetchImpl, onAuthorize: async authUrl => {
    const url = new URL(authUrl); assert.equal(url.origin + url.pathname, `${CORELY_ISSUER}/authorize`);
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    const callback = new URL(CORELY_REDIRECT); callback.searchParams.set('iss', CORELY_ISSUER);
    callback.searchParams.set('state', url.searchParams.get('state')); callback.searchParams.set('code', 'c'.repeat(43));
    const result = await fetch(callback); assert.equal(result.status, 200);
  } });
  validateCorelyStatus(await session.call('corely_work_candidate_status'));
  await assert.rejects(session.call('approve'), /INVALID_OPTIONS/);
  await session.revoke();
  await assert.rejects(session.call('corely_work_candidate_status'), /INVALID_OPTIONS/);
  const tokenRequest = requests.find(row => row.url.endsWith('/token'));
  assert.equal(new URLSearchParams(tokenRequest.options.body).get('code_verifier').length, 43);
  assert.equal(requests.at(-1).url, `${CORELY_ISSUER}/revoke`);
});
