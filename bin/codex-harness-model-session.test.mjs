import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, before, test } from 'node:test';
import { createManagedModelSession, ModelSessionError, snapshotModelRequest } from './codex-harness-model-session.mjs';
import { CANARY_PROFILE, canaryExecutableSha256 } from './codex-harness-permissions-canary.mjs';

// Generated synthetic stdio fixtures only. Never start real Codex, authenticate,
// open a socket, read a credential cache or consume plan/API allowance here.
const originalFetch = globalThis.fetch;
before(() => { globalThis.fetch = async () => { throw new Error('NETWORK_DISABLED_IN_TEST'); }; });
after(() => { globalThis.fetch = originalFetch; });
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const sha = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const schema = () => ({ type: 'object', properties: { answer: { type: 'string', minLength: 1 } }, required: ['answer'], additionalProperties: false });
const remoteStatus = status => ({ status, installationId: 'synthetic-installation', serverName: 'synthetic-server', environmentId: null });
let sequence = 0;
function request(overrides = {}) {
  const content = { version: 1, callId: `synthetic-call-${++sequence}`, workload: 'REPLY_LLM', purpose: 'reply_generation',
    model: 'gpt-6.1-sol', scope: { tenantId: 'moztech', brandId: 'moztech-test', synthetic: true, jobId: 'synthetic-job' },
    system: 'Synthetic system instructions only. Use the supplied synthetic facts.', user: 'Synthetic customer-free question.',
    reasoningEffort: 'low', verbosity: 'low', ...overrides };
  content.schemaSha256 = content.responseSchema ? sha(content.responseSchema) : null;
  return { ...content, inputSha256: sha(content) };
}

async function fixture(scenario, action) {
  const root = await mkdtemp(join(tmpdir(), 'corely-managed-model-offline-'));
  const executable = join(root, 'fake-official'), log = join(root, 'fixture.jsonl');
  const script = `#!${process.execPath}
const fs = require('node:fs'), readline = require('node:readline');
const scenario = ${JSON.stringify(scenario)}, log = ${JSON.stringify(log)};
const record = value => fs.appendFileSync(log, JSON.stringify(value) + '\\n');
const send = value => process.stdout.write(JSON.stringify(value) + '\\n');
const reply = (id, result) => send({id,result}), notify = (method,params) => send({method,params});
let authenticated = !scenario.login, reads = 0, threadCount = 0, active;
record({kind:'boot',argv:process.argv.slice(2),home:process.env.HOME,codexHome:process.env.CODEX_HOME,
  homeEntries:fs.readdirSync(process.env.HOME),codexEntries:fs.readdirSync(process.env.CODEX_HOME),
  homeMode:fs.statSync(process.env.HOME).mode & 511, codexMode:fs.statSync(process.env.CODEX_HOME).mode & 511,
  envKeys:Object.keys(process.env).sort(),cwd:process.cwd()});
function complete(params) {
  if (scenario.earlyExit) return process.exit(0);
  if (scenario.overflow) return process.stdout.write('x'.repeat(1048577));
  const threadId = active.threadId, turnId = active.turnId;
  if (scenario.toolRequest) return send({id:999,method:'item/commandExecution/requestApproval',params:{threadId,turnId,command:'never execute'}});
  if (scenario.unknownAction) return notify('item/futureToolAction',{threadId,turnId});
  if (scenario.reroute) return notify('model/rerouted',{threadId,turnId,fromModel:'gpt-6.1-sol',toModel:'another-model'});
  if (scenario.authDriftEvent) return notify('account/updated',{authMode:'apiKey'});
  if (scenario.activeRemoteParams !== undefined) return notify('remoteControl/status/changed',scenario.activeRemoteParams);
  notify('remoteControl/status/changed',${JSON.stringify(remoteStatus('disabled'))});
  if (scenario.otherWarning) return notify('warning',{threadId,message:'synthetic-secret-warning-not-for-output'});
  notify('warning',{threadId,message:${JSON.stringify('Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed; enable `features.code_mode_host` and install `codex-code-mode-host`.')}});
  notify('future/metadata',{syntheticSecret:'must not enter receipt',completed:true});
  if (scenario.hang) return;
  const errorCode = scenario.quota ? 'usageLimitExceeded' : scenario.errorCode;
  if (errorCode) {
    notify('error',{threadId,turnId,error:{codexErrorInfo:errorCode,message:'synthetic-upstream-secret'},willRetry:scenario.willRetry === true});
    return notify('turn/completed',{threadId,turn:{id:turnId,status:'failed',error:{codexErrorInfo:errorCode,message:'synthetic-upstream-secret'},
      items:scenario.quotaToolItem ? [{id:'forbidden',type:'commandExecution'}] : []}});
  }
  const text = scenario.output ?? 'Synthetic answer.';
  const final = {id:'answer-'+threadCount,type:'agentMessage',phase:'final_answer',text};
  notify('item/completed',{threadId,turnId,item:{id:'user-'+threadCount,type:'userMessage',content:scenario.badEcho ? [{type:'text',text:'wrong input'}] : params.input}});
  if (scenario.commentary) notify('item/completed',{threadId,turnId,item:{id:'commentary',type:'agentMessage',phase:'commentary',text:'Not a final answer.'}});
  if (scenario.toolItem) notify('item/completed',{threadId,turnId,item:{id:'tool',type:'mcpToolCall'}});
  if (!scenario.noFinal) notify('item/completed',{threadId:scenario.crossThread ? 'foreign-thread' : threadId,
    ...(scenario.missingTurnId ? {} : {turnId:scenario.crossTurn ? 'foreign-turn' : turnId}),item:final});
  if (scenario.duplicateFinal) notify('item/completed',{threadId,turnId,item:{...final,id:'another-answer'}});
  if (!scenario.noUsage) notify('thread/tokenUsage/updated',{threadId,turnId,
    tokenUsage:{last:scenario.usage ?? {inputTokens:17,outputTokens:5,cachedInputTokens:2}}});
  if (scenario.hashDrift) fs.appendFileSync(process.argv[1],'\\n// synthetic changed binary fixture');
  notify('turn/completed',{threadId,turn:{id:scenario.completeWrongTurn ? 'foreign-turn' : turnId,
    status:scenario.failed ? 'failed' : 'completed',error:scenario.failed ? {codexErrorInfo:'other',message:'synthetic-secret'} : null,
    items:scenario.noItems ? undefined : [{...final,text:scenario.finalMismatch ? 'not the same final' : text}]}});
  if (scenario.lateQuota) notify('error',{threadId,turnId,error:{codexErrorInfo:'usageLimitExceeded',message:'synthetic-private'},willRetry:false});
}
readline.createInterface({input:process.stdin}).on('line',line=>{
  const message=JSON.parse(line),{id,method,params}=message;
  record({kind:'request',method,params});
  if(method==='initialize') { reply(id,{}); return notify('remoteControl/status/changed',${JSON.stringify(remoteStatus('disabled'))}); }
  if(method==='initialized') return;
  if(method==='account/read') {
    reads++;
    const email = scenario.wrong || (scenario.driftAfter && reads > scenario.driftAfter) ? 'other@example.invalid'
      : scenario.account === 'eason' ? 'moztecheason@gmail.com' : 'info@moztech.cc';
    return reply(id,{requiresOpenaiAuth:scenario.noAuthRequired ? false : true,
      account:authenticated ? {type:scenario.api ? 'apiKey' : 'chatgpt',email,
        planType:scenario.plan ?? 'pro',accessToken:'synthetic-auth-value-never-for-receipt'} : null});
  }
  if(method==='account/login/start') {
    reply(id,{type:'chatgpt',loginId:'synthetic-login',authUrl:scenario.badLogin ? 'https://auth.openai.com.evil.invalid/oauth' : 'https://auth.openai.com/oauth/authorize?state=synthetic'});
    authenticated=true; if (scenario.loginNeverCompletes) return;
    return notify('account/login/completed',{success:true,loginId:scenario.badLoginId ? 'wrong-login' : 'synthetic-login'});
  }
  if(method==='model/list') {
    if (scenario.idleRemoteParams !== undefined) notify('remoteControl/status/changed',scenario.idleRemoteParams);
    return reply(id,{data:scenario.noModel ? [] : [{model:'gpt-6.1-sol',hidden:scenario.hidden === true,
      defaultReasoningEffort:'low',supportedReasoningEfforts:[{reasoningEffort:'low'},{reasoningEffort:'high'}],inputModalities:['text','image']}],nextCursor:null});
  }
  if(method==='thread/start') {
    threadCount++; const threadId=scenario.reuseThread ? 'reused-thread' : 'thread-'+threadCount;
    active={threadId,turnId:'turn-'+threadCount};
    notify('thread/started',{thread:{id:threadId}});
    if (scenario.prematureTurn) {
      notify('turn/started',{threadId,turn:{id:active.turnId,status:'inProgress'}});
      notify('item/completed',{threadId,turnId:active.turnId,item:{id:'premature',type:'agentMessage',phase:'final_answer',text:'Never accept this pre-admission answer.'}});
      notify('thread/tokenUsage/updated',{threadId,turnId:active.turnId,tokenUsage:{last:{inputTokens:1,outputTokens:1,cachedInputTokens:0}}});
      notify('turn/completed',{threadId,turn:{id:active.turnId,status:'completed',error:null,items:[{id:'premature',type:'agentMessage',phase:'final_answer',text:'Never accept this pre-admission answer.'}]}});
    }
    return reply(id,{model:scenario.wrongModel ? 'other-model' : 'gpt-6.1-sol',modelProvider:'openai',
      thread:{id:threadId,modelProvider:'openai',ephemeral:scenario.persistent ? false : true},
      cwd:params.cwd,runtimeWorkspaceRoots:scenario.wrongRoots ? [] : params.runtimeWorkspaceRoots,
      approvalPolicy:params.approvalPolicy,activePermissionProfile:{id:scenario.wrongProfile ? 'broad' : ${JSON.stringify(CANARY_PROFILE)}},
      sandbox:{type:'readOnly',networkAccess:scenario.network === true},instructionSources:scenario.instructions ? ['/synthetic/unexpected'] : []});
  }
  if(method==='turn/start') {
    if(scenario.notifyBeforeReply) notify('turn/started',{threadId:active.threadId,turn:{id:active.turnId,status:'inProgress'}});
    reply(id,{turn:{id:active.turnId}});
    const start=()=>{ if(!scenario.notifyBeforeReply) notify('turn/started',{threadId:active.threadId,turn:{id:active.turnId,status:'inProgress'}}); complete(params); };
    return scenario.delayedStart ? setImmediate(start) : start();
  }
  if(method==='turn/interrupt') {
    if(scenario.ignoreInterrupt) return;
    reply(id,{}); return notify('turn/completed',{threadId:active.threadId,turn:{id:active.turnId,status:'interrupted',error:null,items:[]}});
  }
  if(method==='thread/unsubscribe') return reply(id,{status:scenario.badUnsubscribe ? 'notSubscribed' : 'unsubscribed'});
  return send({id,error:{message:'synthetic-private-error-not-for-receipt'}});
}).on('close',()=>process.exit(0));
`;
  await writeFile(executable, script, { mode: 0o700 });
  const binaryHash = await canaryExecutableSha256(executable);
  let canaries = 0;
  const permissionCanary = async options => {
    canaries++;
    assert.deepEqual(Object.keys(options.sourceEnv).sort(), ['LANG', 'TZ']);
    return { status: 'PERMISSION_CANARY_PASSED', permissionProfile: CANARY_PROFILE,
      insideReadAllowed: true, outsideFixtureReadDenied: true, outsideSymlinkReadDenied: true,
      slashTemporaryFixtureReadDenied: true, slashTemporarySymlinkReadDenied: true,
      workspaceCreateDenied: true, workspaceModifyDenied: true, networkControlVerified: true,
      sandboxNetworkToolStarted: true, loopbackNetworkDenied: true, modelRequestsMade: 0, existingAuthCacheRead: false,
      executableSha256: binaryHash, ...(scenario.badCanary && canaries > 1 ? { slashTemporaryFixtureReadDenied: false } : {}) };
  };
  const options = { executable, account: scenario.account ?? 'info', permissionCanary,
    sourceEnv: { HOME: '/must-not-use-existing-home', CODEX_HOME: '/must-not-use-credential-cache', PATH: '/must-not-inherit',
      LANG: 'en_US.UTF-8', TZ: 'UTC', OPENAI_API_KEY: 'synthetic-secret', NODE_OPTIONS: 'synthetic-secret', HTTPS_PROXY: 'synthetic-secret' },
    rpcTimeoutMs: 5000, cleanupTimeoutMs: 1000, turnTimeoutMs: 10000, loginTimeoutMs: 5000 };
  const records = async () => {
    try { return (await readFile(log, 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line)); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  };
  try { await action({ options, records, executable, canaries: () => canaries }); }
  finally { await rm(root, { recursive: true, force: true }); }
}

test('immutable request snapshot reproduces full Corely canonical hashes without invoking accessors', () => {
  const input = request({ responseFormat: 'json', responseSchema: schema() });
  const snapshot = snapshotModelRequest(input);
  input.scope.jobId = 'changed'; input.responseSchema.properties.answer.type = 'number';
  assert.equal(snapshot.scope.jobId, 'synthetic-job');
  assert.equal(snapshot.responseSchema.properties.answer.type, 'string');
  assert.ok(Object.isFrozen(snapshot.responseSchema.properties.answer));
  let invoked = false;
  const accessor = request(); Object.defineProperty(accessor, 'user', { enumerable: true, get() { invoked = true; return 'not safe'; } });
  assert.throws(() => snapshotModelRequest(accessor), { code: 'INVALID_REQUEST' }); assert.equal(invoked, false);
});

test('request admission rejects foreign scope, image, unsupported schema, mutated hash, hidden fields and non-JSON values', async t => {
  for (const [label, mutate, code] of [
    ['foreign brand', r => { r.scope.brandId = 'real-brand'; }, 'SCOPE_NOT_ADMITTED'],
    ['not synthetic', r => { r.scope.synthetic = false; }, 'SCOPE_NOT_ADMITTED'],
    ['coerced job', r => { r.scope.jobId = 42; }, 'SCOPE_NOT_ADMITTED'],
    ['coerced call', r => { r.callId = 42; }, 'INVALID_REQUEST'],
    ['model', r => { r.model = 'gpt-6'; }, 'INVALID_REQUEST'],
    ['image', r => { r.image = { mime: 'image/png', base64: 'synthetic' }; }, 'UNSUPPORTED_CAPABILITY'],
    ['unsupported schema', r => { r.responseSchema = { type: 'object', oneOf: [] }; }, 'UNSUPPORTED_CAPABILITY'],
    ['changed prompt', r => { r.user += ' changed'; }, 'INPUT_MISMATCH'],
    ['changed schema digest', r => { r.schemaSha256 = 'a'.repeat(64); }, 'INPUT_MISMATCH'],
    ['extra field', r => { r.token = 'synthetic-secret'; }, 'INVALID_REQUEST'],
    ['undefined', r => { r.responseSchema = undefined; }, 'INVALID_REQUEST'],
    ['prototype', r => { Object.setPrototypeOf(r.scope, { unsafe: true }); }, 'INVALID_REQUEST'],
    ['nonfinite', r => { r.scope.unsafe = Infinity; }, 'INVALID_REQUEST'],
  ]) await t.test(label, () => { const input = request(); mutate(input); assert.throws(() => snapshotModelRequest(input), { code }); });
});

test('warm session keeps auth in distinct empty homes and independently isolates every full model call', async () => {
  await fixture({}, async ({ options, records, canaries }) => {
    const session = await createManagedModelSession(options);
    try {
      assert.deepEqual(session.capabilities, { text: true, structuredJson: true, images: false });
      const first = request({ system: 'Full synthetic system. Do not truncate this rule.', user: 'First synthetic question.' });
      const second = request({ purpose: 'semantic_reply_review', user: 'Independent synthetic review task.' });
      const [a, b] = await Promise.all([session.generate(first, new AbortController().signal), session.generate(second, new AbortController().signal)]);
      assert.equal(a.status, 'success'); assert.equal(b.status, 'success'); assert.equal(a.authMode, 'managed_chatgpt');
      assert.equal(a.inputSha256, first.inputSha256); assert.equal(b.callId, second.callId);
      assert.deepEqual(a.usage, { inputTokens: 17, outputTokens: 5, cachedInputTokens: 2 });
      assert.deepEqual(Object.keys(a).sort(), ['accountAlias', 'accountVerified', 'authMode', 'callId', 'completionStatus', 'inputSha256', 'model', 'schemaSha256', 'status', 'text', 'usage']);
      assert.equal(canaries(), 3);
      const log = await records(), boot = log[0], calls = log.filter(row => row.kind === 'request');
      assert.deepEqual(boot.homeEntries, []); assert.deepEqual(boot.codexEntries, []);
      assert.equal(boot.homeMode, 0o700); assert.equal(boot.codexMode, 0o700); assert.notEqual(boot.home, boot.codexHome);
      const platformKeys = process.platform === 'darwin' ? ['__CF_USER_TEXT_ENCODING'] : [];
      assert.deepEqual(boot.envKeys.filter(key => !platformKeys.includes(key)), ['CODEX_HOME', 'HOME', 'LANG', 'PATH', 'TMPDIR', 'TZ']);
      assert.ok(!boot.envKeys.some(key => /API|TOKEN|PROXY|NODE|BASE_URL|PROVIDER/i.test(key)));
      assert.equal(log.filter(row => row.kind === 'boot').length, 1);
      const starts = calls.filter(row => row.method === 'thread/start');
      assert.equal(starts.length, 2); assert.notEqual(starts[0].params.cwd, starts[1].params.cwd);
      assert.equal(starts[0].params.baseInstructions, first.system);
      assert.equal(starts[1].params.baseInstructions, second.system);
      assert.ok(!JSON.stringify(starts[0].params).includes(first.callId));
      assert.deepEqual(starts[0].params.config, { model_reasoning_effort: 'low', model_verbosity: 'low' });
      for (const row of starts) {
        assert.equal(row.params.permissions, CANARY_PROFILE); assert.equal(row.params.ephemeral, true);
        assert.equal(row.params.allowProviderModelFallback, false); assert.equal(row.params.modelProvider, 'openai');
        assert.deepEqual(row.params.dynamicTools, []); assert.deepEqual(row.params.environments, []);
        assert.equal(row.params.sandbox, undefined);
      }
      const order = calls.filter(row => ['thread/start', 'turn/start', 'thread/unsubscribe'].includes(row.method)).map(row => row.method);
      assert.deepEqual(order, ['thread/start', 'turn/start', 'thread/unsubscribe', 'thread/start', 'turn/start', 'thread/unsubscribe']);
      assert.doesNotMatch(JSON.stringify({ a, b, metadata: session.metadata }), /synthetic-auth-value|upstream-secret|accessToken|authUrl/);
      assert.equal(session.metadata.exactPlanDebitAttested, false);
      await assert.rejects(session.generate(first, new AbortController().signal), { code: 'CALL_REPLAY' });
    } finally { await session.close(); }
    const boot = (await records())[0];
    await assert.rejects(access(boot.home), { code: 'ENOENT' });
    await assert.rejects(access(boot.codexHome), { code: 'ENOENT' });
  });
});

test('Info and Eason are separately explicit sessions, never implicit account rotation', async () => {
  await fixture({ account: 'eason' }, async ({ options }) => {
    const session = await createManagedModelSession(options);
    try { const result = await session.generate(request(), new AbortController().signal); assert.equal(result.accountAlias, 'eason'); }
    finally { await session.close(); }
  });
});

test('only explicit official login ceremony is accepted and no login token enters metadata', async t => {
  await fixture({ login: true }, async ({ options, records }) => {
    await assert.rejects(createManagedModelSession(options), { code: 'AUTH_REQUIRED' });
    assert.equal((await records()).some(row => row.method === 'account/login/start'), false);
  });
  await fixture({ login: true }, async ({ options }) => {
    let url;
    const session = await createManagedModelSession({ ...options, login: true, onLogin: async value => { url = new URL(value); } });
    try { assert.equal(url.origin, 'https://auth.openai.com'); assert.equal(session.metadata.authMode, 'managed_chatgpt'); }
    finally { await session.close(); }
  });
  for (const scenario of [{ login: true, badLogin: true }, { login: true, badLoginId: true }]) await t.test(JSON.stringify(scenario), async () => {
    await fixture(scenario, async ({ options }) => assert.rejects(createManagedModelSession({ ...options, login: true, onLogin: async () => {} }), { code: 'LOGIN_FAILED' }));
  });
  await t.test('a stuck UI callback cannot outlive the native login deadline', async () => {
    await fixture({ login: true, loginNeverCompletes: true }, async ({ options }) => {
      await assert.rejects(createManagedModelSession({ ...options, login: true, loginTimeoutMs: 200,
        onLogin: () => new Promise(() => {}) }), { code: 'TIMEOUT' });
    });
  });
});

test('wrong/API/unpaid identity stops before discovery, threads and model requests', async t => {
  for (const scenario of [{ wrong: true }, { api: true }, { plan: 'free' }, { plan: 'unknown' }, { plan: 'business' }, { noAuthRequired: true }]) {
    await t.test(JSON.stringify(scenario), async () => fixture(scenario, async ({ options, records }) => {
      await assert.rejects(createManagedModelSession(options), ModelSessionError);
      const log = await records(); assert.equal(log.some(row => ['model/list', 'thread/start', 'turn/start'].includes(row.method)), false);
    }));
  }
});

test('unavailable/hidden models and unsupported efforts hold before any turn; supported effort is preserved', async t => {
  for (const scenario of [{ noModel: true }, { hidden: true }]) await t.test(JSON.stringify(scenario), async () => {
    await fixture(scenario, async ({ options, records }) => {
      await assert.rejects(createManagedModelSession(options), { code: 'MODEL_UNAVAILABLE' });
      assert.equal((await records()).some(row => row.method === 'thread/start'), false);
    });
  });
  await fixture({}, async ({ options, records }) => {
    const session = await createManagedModelSession(options);
    try {
      await assert.rejects(session.generate(request({ reasoningEffort: 'ultra' }), new AbortController().signal), { code: 'UNSUPPORTED_CAPABILITY' });
      assert.equal((await records()).some(row => row.method === 'thread/start'), false);
      const input = request({ reasoningEffort: 'high' });
      await session.generate(input, new AbortController().signal);
      assert.equal((await records()).find(row => row.method === 'turn/start').params.effort, 'high');
    } finally { await session.close(); }
  });
});

test('full JSON schema is passed unchanged and validated independently, never inferred from a success label', async t => {
  await fixture({ output: '{"answer":"合成回答"}', commentary: true }, async ({ options, records }) => {
    const session = await createManagedModelSession(options);
    try {
      const input = request({ responseSchema: schema(), responseFormat: 'json' });
      const result = await session.generate(input, new AbortController().signal); assert.equal(result.text, '{"answer":"合成回答"}');
      const turn = (await records()).find(row => row.method === 'turn/start'); assert.deepEqual(turn.params.outputSchema, schema());
      assert.deepEqual(turn.params.input, [{ type: 'text', text: input.user }]);
    } finally { await session.close(); }
  });
  for (const output of ['not-json', '{}', '{"answer":""}', '{"answer":"ok","unexpected":true}', '{"answer":42}', '[]']) {
    await t.test(output, async () => fixture({ output }, async ({ options }) => {
      const session = await createManagedModelSession(options);
      try { await assert.rejects(session.generate(request({ responseSchema: schema() }), new AbortController().signal), { code: 'INVALID_STRUCTURED_OUTPUT' }); }
      finally { await session.close(); }
    }));
  }
  await fixture({ output: '{"ok":true}' }, async ({ options, records }) => {
    const session = await createManagedModelSession(options);
    try {
      await session.generate(request({ responseFormat: 'json' }), new AbortController().signal);
      assert.match((await records()).find(row => row.method === 'thread/start').params.developerInstructions, /one valid JSON object/);
    } finally { await session.close(); }
  });
});

test('post-tool composition preserves authoritative supplied results without granting model execution authority', async () => {
  await fixture({ output: 'The supplied verified operation completed successfully.' }, async ({ options, records }) => {
    const session = await createManagedModelSession(options);
    try {
      const input = request({ system: 'Describe only the authoritative operation result supplied by the server. Never invent operation status.',
        user: 'Synthetic server-verified action evidence: {"operation":"synthetic-operation","verified":true,"status":"completed"}.' });
      const result = await session.generate(input, new AbortController().signal);
      assert.equal(result.status, 'success');
      const start = (await records()).find(row => row.method === 'thread/start');
      assert.equal(start.params.baseInstructions, input.system);
      assert.match(start.params.developerInstructions, /may accurately describe a server-verified action result explicitly supplied/);
      assert.match(start.params.developerInstructions, /no authority to execute actions or change state/);
      assert.doesNotMatch(start.params.developerInstructions, /Never claim that an action was executed/);
    } finally { await session.close(); }
  });
});

test('native terminal usageLimitExceeded alone can prove quota exhaustion; other failures never trigger fallback', async t => {
  await fixture({ quota: true }, async ({ options }) => {
    const session = await createManagedModelSession(options);
    try {
      const input = request(), result = await session.generate(input, new AbortController().signal);
      assert.deepEqual(result, { accountAlias: 'info', authMode: 'managed_chatgpt', accountVerified: true, model: 'gpt-6.1-sol',
        callId: input.callId, inputSha256: input.inputSha256, schemaSha256: null, status: 'quota_exhausted', code: 'QUOTA_EXHAUSTED', authenticated: true });
    } finally { await session.close(); }
  });
  for (const scenario of [{ errorCode: 'rateLimitExceeded' }, { errorCode: 'sessionBudgetExceeded' }, { errorCode: 'unauthorized' },
    { errorCode: { httpConnectionFailed: { httpStatusCode: 429 } } }, { quota: true, willRetry: true }, { quota: true, quotaToolItem: true }]) {
    await t.test(JSON.stringify(scenario), async () => fixture(scenario, async ({ options }) => {
      const session = await createManagedModelSession(options);
      try { await assert.rejects(session.generate(request(), new AbortController().signal), ModelSessionError); }
      finally { await session.close(); }
    }));
  }
});

test('adversarial model/tool/protocol/account/source events hold without leaking raw failure content', async t => {
  for (const scenario of [{ toolRequest: true }, { toolItem: true }, { unknownAction: true }, { reroute: true }, { authDriftEvent: true },
    { otherWarning: true }, { crossThread: true }, { crossTurn: true }, { missingTurnId: true }, { badEcho: true }, { noFinal: true },
    { noUsage: true }, { noItems: true }, { duplicateFinal: true }, { finalMismatch: true }, { completeWrongTurn: true },
    { failed: true }, { earlyExit: true }, { overflow: true }, { driftAfter: 3 }, { wrongRoots: true }, { wrongProfile: true },
    { persistent: true }, { wrongModel: true }, { network: true }, { instructions: true }, { badCanary: true }, { hashDrift: true }, { lateQuota: true }, { prematureTurn: true },
    { usage: { inputTokens: 1, outputTokens: 1, cachedInputTokens: 2 } }, { usage: { inputTokens: -1, outputTokens: 1, cachedInputTokens: 0 } }]) {
    await t.test(JSON.stringify(scenario), async () => fixture(scenario, async ({ options }) => {
      const session = await createManagedModelSession(options);
      try {
        await assert.rejects(session.generate(request(), new AbortController().signal), error => {
          assert.ok(error instanceof ModelSessionError); assert.doesNotMatch(JSON.stringify(error), /synthetic-(?:secret|private|upstream)|auth-value/); return true;
        });
      } finally { await session.close(); }
    }));
  }
});

test('only documented native disabled remote status is accepted in both idle and active phases', async t => {
  const adversaries = [
    ['connecting', remoteStatus('connecting')], ['connected', remoteStatus('connected')], ['errored', remoteStatus('errored')],
    ['unknown enum', remoteStatus('future-status')], ['legacy nested false', remoteStatus({ enabled: false })],
    ['missing required metadata', { status: 'disabled', serverName: 'synthetic-server' }],
    ['invalid metadata type', { ...remoteStatus('disabled'), environmentId: 42 }],
  ];
  for (const phase of ['idle', 'active']) for (const [label, params] of adversaries) await t.test(`${phase}: ${label}`, async () => {
    await fixture({ [`${phase}RemoteParams`]: params }, async ({ options, records }) => {
      if (phase === 'idle') {
        await assert.rejects(createManagedModelSession(options), { code: 'UNSUPPORTED_EVENT' });
        assert.equal((await records()).some(row => ['thread/start', 'turn/start'].includes(row.method)), false);
      } else {
        const session = await createManagedModelSession(options);
        try { await assert.rejects(session.generate(request(), new AbortController().signal), { code: 'UNSUPPORTED_EVENT' }); }
        finally { await session.close(); }
      }
    });
  });
});

test('filesystem setup and hostile descriptor errors expose only fixed public codes', async () => {
  const hostile = new Proxy(request(), { getOwnPropertyDescriptor() { throw new Error('synthetic-private-path-or-token'); } });
  assert.throws(() => snapshotModelRequest(hostile), error => {
    assert.equal(error.code, 'INVALID_REQUEST'); assert.doesNotMatch(error.message, /synthetic-private/); return true;
  });
  await fixture({}, async ({ options, executable }) => {
    const badTemporaryRoot = join(dirname(executable), 'synthetic-not-a-directory');
    await writeFile(badTemporaryRoot, 'Synthetic fixture only.');
    const previous = process.env.TMPDIR;
    try {
      process.env.TMPDIR = badTemporaryRoot;
      await assert.rejects(createManagedModelSession(options), error => {
        assert.ok(error instanceof ModelSessionError); assert.doesNotMatch(error.message, /not-a-directory|corely-managed-model-offline/); return true;
      });
    } finally {
      if (previous === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = previous;
    }
  });
});

test('official response-before-notification and notification-before-response races preserve turn identity', async t => {
  for (const scenario of [{ delayedStart: true }, { notifyBeforeReply: true }]) await t.test(JSON.stringify(scenario), async () => {
    await fixture(scenario, async ({ options }) => {
      const session = await createManagedModelSession(options);
      try { assert.equal((await session.generate(request(), new AbortController().signal)).status, 'success'); }
      finally { await session.close(); }
    });
  });
});

test('abort and timeout interrupt then unsubscribe; a queued aborted job never starts', async t => {
  await fixture({ hang: true }, async ({ options, records }) => {
    const session = await createManagedModelSession(options), first = new AbortController(), queued = new AbortController();
    try {
      const running = session.generate(request(), first.signal); running.catch(() => {});
      const pending = session.generate(request(), queued.signal); queued.abort();
      await assert.rejects(pending, { code: 'ABORTED' });
      while (!(await records()).some(row => row.method === 'turn/start')) await new Promise(resolve => setImmediate(resolve));
      // Wait until the fixture's start notification has reached the parent.
      await new Promise(resolve => setImmediate(resolve)); first.abort();
      await assert.rejects(running, { code: 'ABORTED' });
      await session.close();
      const log = await records(); assert.equal(log.filter(row => row.method === 'turn/start').length, 1);
      assert.deepEqual(log.filter(row => ['turn/interrupt', 'thread/unsubscribe'].includes(row.method)).map(row => row.method), ['turn/interrupt', 'thread/unsubscribe']);
    } finally { await session.close(); }
  });
  await t.test('unconfirmed interrupt kills the warm session instead of returning a candidate', async () => {
    await fixture({ hang: true, ignoreInterrupt: true }, async ({ options }) => {
      const session = await createManagedModelSession({ ...options, turnTimeoutMs: 80 });
      try { await assert.rejects(session.generate(request(), new AbortController().signal), { code: 'CLEANUP_FAILED' }); }
      finally { await session.close(); }
    });
  });
});

test('already aborted inputs and owner session close cannot start or leave an active model call waiting', async t => {
  await fixture({}, async ({ options, records, canaries }) => {
    const session = await createManagedModelSession(options), controller = new AbortController(); controller.abort();
    try {
      await assert.rejects(session.generate(request(), controller.signal), { code: 'ABORTED' });
      assert.equal(canaries(), 1); assert.equal((await records()).some(row => row.method === 'thread/start'), false);
    } finally { await session.close(); }
  });
  await t.test('closing an active session rejects the call and removes empty homes', async () => {
    await fixture({ hang: true }, async ({ options, records }) => {
      const session = await createManagedModelSession(options);
      const running = session.generate(request(), new AbortController().signal); running.catch(() => {});
      while (!(await records()).some(row => row.method === 'turn/start')) await new Promise(resolve => setImmediate(resolve));
      await session.close(); await assert.rejects(running, ModelSessionError);
      await assert.rejects(session.generate(request(), new AbortController().signal), { code: 'SESSION_CLOSED' });
      await assert.rejects(access((await records())[0].codexHome), { code: 'ENOENT' });
    });
  });
});

test('unsubscribed proof is required before success and a reused thread is rejected', async t => {
  await fixture({ badUnsubscribe: true }, async ({ options }) => {
    const session = await createManagedModelSession(options);
    try { await assert.rejects(session.generate(request(), new AbortController().signal), { code: 'CLEANUP_FAILED' }); }
    finally { await session.close(); }
  });
  await t.test('previous thread cannot carry into a later model call', async () => fixture({ reuseThread: true }, async ({ options }) => {
    const session = await createManagedModelSession(options);
    try { await session.generate(request(), new AbortController().signal); await assert.rejects(session.generate(request(), new AbortController().signal), { code: 'THREAD_MISMATCH' }); }
    finally { await session.close(); }
  }));
});
