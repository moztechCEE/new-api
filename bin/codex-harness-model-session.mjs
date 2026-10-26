// Local, owner-operated official Codex model port. No listener, API provider,
// token import, existing credential cache, account rotation or command entrypoint.
// Recognizable hosted invocation is rejected; absence of a marker does not
// attest local-use eligibility or authorize a commercial/hosted service.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { MODEL, HARNESS_ACCOUNTS, verifyAccount } from './codex-harness-pilot.mjs';
import { CANARY_PROFILE, canaryExecutableSha256, canaryProfileOverrides, runPermissionsCanary } from './codex-harness-permissions-canary.mjs';

export const MODEL_SESSION_VERSION = 'corely-managed-model-session-v1';
const BOUNDARY = 'This is an owner-operated synthetic Corely model call. Follow the supplied base instructions for this call only. Produce the requested answer without tools, files, network, apps, subagents, execution, approval, sending, learning or persistence. The model has no authority to execute actions or change state. It may accurately describe a server-verified action result explicitly supplied in this call; never invent success, completion or execution evidence.';
const DISABLED_WARNING = 'Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed; enable `features.code_mode_host` and install `codex-code-mode-host`.';
const DISABLED = ['shell_tool', 'unified_exec', 'apps', 'plugins', 'hooks', 'browser_use', 'browser_use_external',
  'computer_use', 'image_generation', 'code_mode_host', 'multi_agent', 'multi_agent_v2', 'memories', 'chronicle',
  'skill_search', 'view_image', 'sleep_tool', 'in_app_browser', 'unbounded_connection_retries'];
const HOSTED_EXECUTION_MARKERS = ['K_SERVICE', 'K_REVISION', 'K_CONFIGURATION', 'CLOUD_RUN_JOB', 'CLOUD_RUN_EXECUTION',
  'CLOUD_RUN_TASK_INDEX', 'CLOUD_RUN_TASK_ATTEMPT', 'CLOUD_RUN_TASK_COUNT', 'CLOUD_RUN_WORKER_POOL', 'CLOUD_RUN_REVISION'];
const CODES = new Set(['INVALID_OPTIONS', 'INVALID_REQUEST', 'SCOPE_NOT_ADMITTED', 'UNSUPPORTED_CAPABILITY', 'INPUT_MISMATCH',
  'HOSTED_EXECUTION_REJECTED',
  'AUTH_REQUIRED', 'LOGIN_FAILED', 'WRONG_ACCOUNT', 'AUTH_MODE_REJECTED', 'PLAN_UNVERIFIED', 'MODEL_UNAVAILABLE', 'MODEL_CHANGED',
  'SANDBOX_UNVERIFIED', 'RUNTIME_CHANGED', 'UNEXPECTED_INSTRUCTIONS', 'SPAWN_FAILED', 'PROCESS_FAILED', 'PROTOCOL_ERROR',
  'RPC_FAILED', 'TIMEOUT', 'OUTPUT_LIMIT', 'TOOL_USE_REJECTED', 'UNSUPPORTED_EVENT', 'THREAD_MISMATCH', 'TURN_MISMATCH',
  'TURN_FAILED', 'INCOMPLETE_TURN', 'INVALID_USAGE', 'INVALID_OUTPUT', 'INVALID_STRUCTURED_OUTPUT', 'CALL_REPLAY',
  'SESSION_CLOSED', 'ABORTED', 'CLEANUP_FAILED']);
const REQUEST_KEYS = new Set(['version', 'callId', 'workload', 'purpose', 'model', 'scope', 'system', 'user', 'responseFormat',
  'responseSchema', 'image', 'reasoningEffort', 'verbosity', 'inputSha256', 'schemaSha256']);
const WORKLOADS = new Set(['DECISION_LLM', 'REPLY_LLM', 'WEB_CHAT_VISION', 'MEDIA_IMAGE_ANALYSIS']);
const PURPOSES = new Set(['semantic_reply_review', 'semantic_evidence_selection', 'support_decision', 'reply_generation',
  'reply_repair', 'structured_output', 'text_generation', 'image_analysis']);
const SCHEMA_KEYS = new Set(['type', 'description', 'title', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const',
  'minItems', 'maxItems', 'minLength', 'maxLength', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'uniqueItems']);
const TYPES = new Set(['null', 'object', 'array', 'string', 'integer', 'number', 'boolean']);
const CAPABILITIES = Object.freeze({ text: true, structuredJson: true, images: false });
const MAX_BYTES = 1024 * 1024;

export class ModelSessionError extends Error {
  constructor(code) { super(CODES.has(code) ? code : 'PROTOCOL_ERROR'); this.name = 'ModelSessionError'; this.code = this.message; }
}
const held = code => { throw new ModelSessionError(code); };
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  promise.catch(() => {});
  return { promise, resolve, reject };
};

// Rebuild caller JSON synchronously, without invoking getters or retaining
// references. This canonical order is the Corely router's SHA-256 contract.
function copyCanonical(value) {
  let nodes = 0;
  const seen = new Set();
  const visit = (node, depth) => {
    if (++nodes > 20000 || depth > 32) held('INVALID_REQUEST');
    if (node === null || typeof node === 'string' || typeof node === 'boolean') return node;
    if (typeof node === 'number' && Number.isFinite(node)) return node;
    if (!node || typeof node !== 'object' || seen.has(node) || Object.getOwnPropertySymbols(node).length) held('INVALID_REQUEST');
    if (!Array.isArray(node) && ![Object.prototype, null].includes(Object.getPrototypeOf(node))) held('INVALID_REQUEST');
    seen.add(node);
    const descriptors = Object.getOwnPropertyDescriptors(node);
    let result;
    if (Array.isArray(node)) {
      if (Object.keys(descriptors).some(key => key !== 'length' && !/^(0|[1-9][0-9]*)$/.test(key))) held('INVALID_REQUEST');
      result = [];
      for (let index = 0; index < node.length; index++) {
        const entry = descriptors[index];
        if (!entry || !entry.enumerable || !Object.hasOwn(entry, 'value')) held('INVALID_REQUEST');
        result.push(visit(entry.value, depth + 1));
      }
    } else {
      result = Object.fromEntries(Object.keys(descriptors).sort().map(key => {
        const entry = descriptors[key];
        if (!entry.enumerable || !Object.hasOwn(entry, 'value')) held('INVALID_REQUEST');
        return [key, visit(entry.value, depth + 1)];
      }));
    }
    seen.delete(node);
    return Object.freeze(result);
  };
  const result = visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(result)) > 8 * MAX_BYTES) held('INVALID_REQUEST');
  return result;
}

function supportsSchema(schema) {
  let nodes = 0;
  const visit = (s, depth) => {
    if (++nodes > 2000 || depth > 24 || !s || typeof s !== 'object' || Array.isArray(s) ||
        Object.keys(s).some(key => !SCHEMA_KEYS.has(key))) return false;
    const types = Array.isArray(s.type) ? s.type : [s.type];
    if (!types.length || types.some(type => !TYPES.has(type))) return false;
    if (s.enum !== undefined && (!Array.isArray(s.enum) || !s.enum.length)) return false;
    if (s.uniqueItems !== undefined && typeof s.uniqueItems !== 'boolean') return false;
    for (const key of ['title', 'description']) if (s[key] !== undefined && typeof s[key] !== 'string') return false;
    for (const key of ['minItems', 'maxItems', 'minLength', 'maxLength']) {
      if (s[key] !== undefined && (!Number.isSafeInteger(s[key]) || s[key] < 0)) return false;
    }
    for (const key of ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum']) {
      if (s[key] !== undefined && (typeof s[key] !== 'number' || !Number.isFinite(s[key]))) return false;
    }
    if (types.includes('object')) {
      if (s.additionalProperties !== false || !s.properties || typeof s.properties !== 'object' || Array.isArray(s.properties) ||
          !Array.isArray(s.required) || s.required.some(key => typeof key !== 'string' || !Object.hasOwn(s.properties, key)) ||
          new Set(s.required).size !== s.required.length || !Object.values(s.properties).every(child => visit(child, depth + 1))) return false;
    }
    if (types.includes('array') && !visit(s.items, depth + 1)) return false;
    return true;
  };
  return visit(schema, 0);
}

function validateOutput(text, request) {
  if (typeof text !== 'string' || !text.trim() || Buffer.byteLength(text) > MAX_BYTES) held('INVALID_OUTPUT');
  if (!request.responseSchema && request.responseFormat !== 'json') return;
  let parsed;
  try { parsed = JSON.parse(text); } catch { held('INVALID_STRUCTURED_OUTPUT'); }
  if (!request.responseSchema) {
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) held('INVALID_STRUCTURED_OUTPUT');
    return;
  }
  let nodes = 0;
  const validate = (value, s, depth) => {
    if (++nodes > 4000 || depth > 24) return false;
    const types = Array.isArray(s.type) ? s.type : [s.type];
    const matches = type => type === 'null' ? value === null : type === 'array' ? Array.isArray(value)
      : type === 'object' ? value !== null && typeof value === 'object' && !Array.isArray(value)
        : type === 'integer' ? Number.isSafeInteger(value) : type === 'number' ? typeof value === 'number' && Number.isFinite(value)
          : typeof value === type;
    if (!types.some(matches)) return false;
    if (s.enum && !s.enum.some(entry => JSON.stringify(copyCanonical(entry)) === JSON.stringify(copyCanonical(value)))) return false;
    if (Object.hasOwn(s, 'const') && JSON.stringify(copyCanonical(s.const)) !== JSON.stringify(copyCanonical(value))) return false;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return s.required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key =>
        Object.hasOwn(s.properties, key) && validate(value[key], s.properties[key], depth + 1));
    }
    if (Array.isArray(value)) return (s.minItems === undefined || value.length >= s.minItems) &&
      (s.maxItems === undefined || value.length <= s.maxItems) &&
      (s.uniqueItems !== true || new Set(value.map(entry => JSON.stringify(copyCanonical(entry)))).size === value.length) &&
      value.every(entry => validate(entry, s.items, depth + 1));
    if (typeof value === 'string' && ((s.minLength !== undefined && [...value].length < s.minLength) ||
        (s.maxLength !== undefined && [...value].length > s.maxLength))) return false;
    return typeof value !== 'number' || !((s.minimum !== undefined && value < s.minimum) || (s.maximum !== undefined && value > s.maximum) ||
      (s.exclusiveMinimum !== undefined && value <= s.exclusiveMinimum) || (s.exclusiveMaximum !== undefined && value >= s.exclusiveMaximum));
  };
  if (!validate(parsed, request.responseSchema, 0)) held('INVALID_STRUCTURED_OUTPUT');
}

function snapshotRequest(input) {
  const request = copyCanonical(input);
  if (!request || typeof request !== 'object' || Array.isArray(request) || Object.keys(request).some(key => !REQUEST_KEYS.has(key)) ||
      request.version !== 1 || request.model !== MODEL || typeof request.callId !== 'string' || !/^[A-Za-z0-9_-]{1,160}$/.test(request.callId) ||
      !WORKLOADS.has(request.workload) || !PURPOSES.has(request.purpose) || typeof request.system !== 'string' || !request.system.trim() ||
      typeof request.user !== 'string' || !request.user.trim() || (request.responseFormat !== undefined && request.responseFormat !== 'json') ||
      (request.verbosity !== undefined && request.verbosity !== 'low') ||
      (request.reasoningEffort !== undefined && (typeof request.reasoningEffort !== 'string' || !/^[a-z][a-z0-9_-]{0,31}$/.test(request.reasoningEffort)))) held('INVALID_REQUEST');
  const s = request.scope;
  if (!s || typeof s !== 'object' || Array.isArray(s) || Object.keys(s).some(key => !['tenantId', 'brandId', 'synthetic', 'jobId'].includes(key)) ||
      s.tenantId !== 'moztech' || s.brandId !== 'moztech-test' || s.synthetic !== true || typeof s.jobId !== 'string' || !/^[A-Za-z0-9_-]{1,160}$/.test(s.jobId)) held('SCOPE_NOT_ADMITTED');
  if (Object.hasOwn(request, 'image')) held('UNSUPPORTED_CAPABILITY');
  if (request.responseSchema !== undefined && !supportsSchema(request.responseSchema)) held('UNSUPPORTED_CAPABILITY');
  const schemaHash = request.responseSchema === undefined ? null : digest(request.responseSchema);
  if (request.schemaSha256 !== schemaHash || !/^[a-f0-9]{64}$/.test(request.inputSha256 ?? '')) held('INPUT_MISMATCH');
  const content = Object.fromEntries(Object.entries(request).filter(([key]) => key !== 'inputSha256'));
  if (digest(content) !== request.inputSha256) held('INPUT_MISMATCH');
  return request;
}

export function snapshotModelRequest(input) {
  try { return snapshotRequest(input); }
  catch (error) { throw error instanceof ModelSessionError ? error : new ModelSessionError('INVALID_REQUEST'); }
}

class OfficialChannel {
  constructor(executable, args, env, cwd, timeoutMs) {
    this.timeoutMs = timeoutMs; this.sequence = 0; this.pending = new Map(); this.waiters = new Map();
    this.bytes = 0; this.buffer = ''; this.decoder = new StringDecoder('utf8'); this.stopped = false;
    this.child = spawn(executable, args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
    this.exited = deferred();
    this.child.on('error', () => this.fail(new ModelSessionError('SPAWN_FAILED')));
    this.child.on('close', () => { this.closed = true; this.exited.resolve(); if (!this.stopped) this.fail(new ModelSessionError('PROCESS_FAILED')); });
    this.child.stdin.on('error', () => this.fail(new ModelSessionError('PROCESS_FAILED')));
    this.child.stderr.on('data', chunk => { this.bytes += chunk.length; if (this.bytes > MAX_BYTES) this.fail(new ModelSessionError('OUTPUT_LIMIT')); });
    this.child.stdout.on('data', chunk => this.consume(chunk));
  }
  resetBudget() { this.bytes = 0; }
  fail(error) {
    this.failure ??= error instanceof ModelSessionError ? error : new ModelSessionError('PROTOCOL_ERROR');
    for (const entry of [...this.pending.values(), ...this.waiters.values()]) { clearTimeout(entry.timer); entry.reject(this.failure); }
    this.pending.clear(); this.waiters.clear(); this.onFailure?.(this.failure); this.child.kill('SIGTERM');
  }
  consume(chunk) {
    if (this.failure) return;
    this.bytes += chunk.length;
    if (this.bytes > MAX_BYTES) return this.fail(new ModelSessionError('OUTPUT_LIMIT'));
    this.buffer += this.decoder.write(chunk);
    while (this.buffer.includes('\n')) {
      const end = this.buffer.indexOf('\n'), line = this.buffer.slice(0, end); this.buffer = this.buffer.slice(end + 1);
      if (!line.trim()) continue;
      try {
        const message = JSON.parse(line);
        if (!message || typeof message !== 'object' || Array.isArray(message)) held('PROTOCOL_ERROR');
        if (Object.hasOwn(message, 'method') && Object.hasOwn(message, 'id')) held('TOOL_USE_REJECTED');
        if (Object.hasOwn(message, 'id')) {
          const entry = this.pending.get(message.id);
          if (!entry) held('PROTOCOL_ERROR');
          clearTimeout(entry.timer); this.pending.delete(message.id);
          if (message.error || !Object.hasOwn(message, 'result')) entry.reject(new ModelSessionError('RPC_FAILED'));
          else entry.resolve(message.result);
        } else {
          if (typeof message.method !== 'string') held('PROTOCOL_ERROR');
          const entry = this.waiters.get(message.method);
          if (entry) { clearTimeout(entry.timer); this.waiters.delete(message.method); entry.resolve(message.params); }
          this.onNotification?.(message.method, message.params);
        }
      } catch (error) { return this.fail(error); }
    }
  }
  rpc(method, params, timeoutMs = this.timeoutMs) {
    if (this.failure || this.stopped) return Promise.reject(this.failure ?? new ModelSessionError('SESSION_CLOSED'));
    const id = ++this.sequence, operation = deferred();
    const timer = setTimeout(() => this.fail(new ModelSessionError('TIMEOUT')), timeoutMs);
    this.pending.set(id, { ...operation, timer });
    this.child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
    return operation.promise;
  }
  wait(method, timeoutMs) {
    if (this.failure || this.stopped || this.waiters.has(method)) return Promise.reject(this.failure ?? new ModelSessionError('PROTOCOL_ERROR'));
    const operation = deferred(), timer = setTimeout(() => this.fail(new ModelSessionError('TIMEOUT')), timeoutMs);
    this.waiters.set(method, { ...operation, timer }); return operation.promise;
  }
  async close() {
    if (this.closing) return this.closing;
    this.closing = (async () => {
      this.stopped = true;
      for (const entry of [...this.pending.values(), ...this.waiters.values()]) { clearTimeout(entry.timer); entry.reject(new ModelSessionError('SESSION_CLOSED')); }
      this.pending.clear(); this.waiters.clear();
      this.child.stdin.end(); this.child.kill('SIGTERM');
      let timer;
      try {
        await Promise.race([this.exited.promise, new Promise((resolve, reject) => {
          timer = setTimeout(() => { this.child.kill('SIGKILL'); timer = setTimeout(() => reject(new ModelSessionError('CLEANUP_FAILED')), 1000); }, 1000);
        })]);
      } finally { clearTimeout(timer); }
    })();
    return this.closing;
  }
}

function validateIdentity(result, account, previousPlan) {
  let receipt;
  try { receipt = verifyAccount(result, HARNESS_ACCOUNTS[account]); }
  catch (error) { held(CODES.has(error?.code) ? error.code : 'AUTH_MODE_REJECTED'); }
  if (!['plus', 'pro'].includes(receipt.planType) || (previousPlan && receipt.planType !== previousPlan)) held('PLAN_UNVERIFIED');
  return receipt.planType;
}

function verifyProof(proof, expectedHash) {
  if (proof?.status !== 'PERMISSION_CANARY_PASSED' || proof.permissionProfile !== CANARY_PROFILE ||
      ['insideReadAllowed', 'outsideFixtureReadDenied', 'outsideSymlinkReadDenied', 'slashTemporaryFixtureReadDenied',
        'slashTemporarySymlinkReadDenied', 'workspaceCreateDenied', 'workspaceModifyDenied', 'networkControlVerified',
        'sandboxNetworkToolStarted', 'loopbackNetworkDenied'].some(key => proof[key] !== true) ||
      proof.modelRequestsMade !== 0 || proof.existingAuthCacheRead !== false || proof.executableSha256 !== expectedHash) held('SANDBOX_UNVERIFIED');
}

class ManagedModelSession {
  constructor(options, root, channel, executableSha256) {
    this.options = options; this.root = root; this.channel = channel; this.executableSha256 = executableSha256;
    this.seenCalls = new Set(); this.seenThreads = new Set(); this.queue = Promise.resolve(); this.capabilities = CAPABILITIES;
    channel.onFailure = error => {
      this.active?.completion.reject(error);
      this.close().catch(() => {});
    };
    channel.onNotification = (method, params) => this.notification(method, params);
  }
  async account() {
    this.plan = validateIdentity(await this.channel.rpc('account/read', { refreshToken: false }), this.options.account, this.plan);
  }
  async model() {
    let cursor;
    for (let page = 0; page < 10; page++) {
      const result = await this.channel.rpc('model/list', { includeHidden: false, limit: 100, ...(cursor ? { cursor } : {}) });
      if (!Array.isArray(result?.data)) held('MODEL_UNAVAILABLE');
      const model = result.data.find(row => row?.model === MODEL && row.hidden === false);
      if (model) {
        if (typeof model.defaultReasoningEffort !== 'string' || !Array.isArray(model.supportedReasoningEfforts)) held('MODEL_UNAVAILABLE');
        this.modelInfo = { defaultEffort: model.defaultReasoningEffort,
          efforts: new Set(model.supportedReasoningEfforts.map(row => row?.reasoningEffort).filter(value => typeof value === 'string')) };
        return;
      }
      if (result.nextCursor == null) break;
      if (typeof result.nextCursor !== 'string' || !result.nextCursor || result.nextCursor === cursor) held('MODEL_UNAVAILABLE');
      cursor = result.nextCursor;
    }
    held('MODEL_UNAVAILABLE');
  }
  notification(method, p) {
    if (method === 'remoteControl/status/changed') {
      // Installed v2 RemoteControlStatusChangedNotification uses a string
      // enum, not { enabled: false }. Disabled metadata grants no capability.
      if (!p || typeof p !== 'object' || Array.isArray(p) || p.status !== 'disabled' ||
          typeof p.installationId !== 'string' || typeof p.serverName !== 'string' ||
          (p.environmentId !== undefined && p.environmentId !== null && typeof p.environmentId !== 'string')) held('UNSUPPORTED_EVENT');
      return;
    }
    if (method === 'account/updated') {
      if (p?.authMode !== 'chatgpt' || (p.planType !== undefined && this.plan && p.planType !== this.plan)) held('AUTH_MODE_REJECTED');
      return;
    }
    const state = this.active;
    if (!state) {
      if (['account/login/completed', 'account/rateLimits/updated', 'thread/closed', 'thread/status/changed'].includes(method)) return;
      if (/^(item|account|auth|model|modelProvider|hook|mcpServer|app|process|command|fs)\//.test(method) || /error|warning|permission|approval/i.test(method)) held('UNSUPPORTED_EVENT');
      return;
    }
    if (!state.threadId) { state.early.push([method, p]); if (state.early.length > 100) held('OUTPUT_LIMIT'); return; }
    if (['turn/started', 'item/started', 'item/completed', 'thread/tokenUsage/updated', 'error', 'turn/completed'].includes(method) &&
        !state.turnRequested) held('PROTOCOL_ERROR');
    if (p?.threadId !== undefined && p.threadId !== state.threadId) held('THREAD_MISMATCH');
    if (['turn/started', 'item/started', 'item/completed', 'thread/tokenUsage/updated', 'error', 'turn/completed'].includes(method) &&
        p?.threadId !== state.threadId) held('THREAD_MISMATCH');
    if (method === 'thread/started') { if (p?.thread?.id !== state.threadId) held('THREAD_MISMATCH'); return; }
    if (method === 'turn/started') {
      if (state.turnStarted || typeof p?.turn?.id !== 'string' || !p.turn.id || (state.turnId && state.turnId !== p.turn.id)) held('PROTOCOL_ERROR');
      state.turnId = p.turn.id; state.turnStarted = true; return;
    }
    if (p?.turnId !== undefined && p.turnId !== state.turnId) held('TURN_MISMATCH');
    if (['item/started', 'item/completed', 'thread/tokenUsage/updated', 'error'].includes(method) &&
        p?.turnId !== state.turnId) held('TURN_MISMATCH');
    if (method === 'item/started' || method === 'item/completed') {
      if (!state.turnId || state.terminal) held('PROTOCOL_ERROR');
      const item = p?.item;
      if (!item || !['userMessage', 'reasoning', 'agentMessage'].includes(item.type)) held('TOOL_USE_REJECTED');
      if (item.type === 'userMessage') {
        if (item.content?.length !== 1 || item.content[0]?.type !== 'text' || item.content[0].text !== state.request.user) held('INPUT_MISMATCH');
        return;
      }
      if (typeof item.id !== 'string' || !item.id) held('PROTOCOL_ERROR');
      if (item.type === 'agentMessage' && method === 'item/completed') {
        if (typeof item.text !== 'string') held('INVALID_OUTPUT');
        if (item.phase == null || item.phase === 'final_answer') {
          if (state.final) held('INVALID_OUTPUT');
          state.final = { id: item.id, text: item.text };
        } else if (!['commentary', 'partial_answer'].includes(item.phase)) held('INVALID_OUTPUT');
      }
      return;
    }
    if (method === 'thread/tokenUsage/updated') {
      if (!state.turnId || state.terminal) held('PROTOCOL_ERROR');
      const usage = p?.tokenUsage?.last;
      if (!usage || ['inputTokens', 'outputTokens', 'cachedInputTokens'].some(key => !Number.isSafeInteger(usage[key]) || usage[key] < 0) ||
          usage.cachedInputTokens > usage.inputTokens) held('INVALID_USAGE');
      state.usage = Object.freeze({ inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, cachedInputTokens: usage.cachedInputTokens });
      return;
    }
    if (method === 'error') {
      if (!state.turnId || state.terminal || p?.error?.codexErrorInfo !== 'usageLimitExceeded' || p.willRetry !== false) held('TURN_FAILED');
      state.nativeQuota = true; return;
    }
    if (method === 'turn/completed') {
      const turn = p?.turn;
      if (!state.turnId || !state.turnStarted || turn?.id !== state.turnId || state.terminal) held('TURN_MISMATCH');
      state.terminal = turn.status;
      if (!Array.isArray(turn.items)) held('INCOMPLETE_TURN');
      for (const item of turn.items) {
        if (!['userMessage', 'reasoning', 'agentMessage'].includes(item?.type)) held('TOOL_USE_REJECTED');
      }
      if (state.aborted && turn.status === 'interrupted') { state.completion.resolve(turn); return; }
      if (turn.status === 'failed' && turn.error?.codexErrorInfo === 'usageLimitExceeded' && !state.final) {
        state.nativeQuota = true; state.completion.resolve(turn); return;
      }
      if (turn.status !== 'completed' || turn.error || state.nativeQuota) held('TURN_FAILED');
      if (!state.final || !state.usage) held('INCOMPLETE_TURN');
      const finalItems = turn.items.filter(item => item.type === 'agentMessage' && (item.phase == null || item.phase === 'final_answer'));
      if (finalItems.length !== 1 || finalItems[0].id !== state.final.id || finalItems[0].text !== state.final.text) held('INVALID_OUTPUT');
      state.completion.resolve(turn); return;
    }
    if (method === 'model/rerouted') held('MODEL_CHANGED');
    if (method === 'warning' && p?.threadId === state.threadId && p?.message === DISABLED_WARNING) return;
    if (['thread/status/changed', 'account/rateLimits/updated', 'item/agentMessage/delta', 'item/reasoning/summaryTextDelta',
      'item/reasoning/summaryPartAdded', 'item/reasoning/textDelta'].includes(method)) return;
    if (/^(item|account|auth|model|modelProvider|hook|mcpServer|app|process|command|fs|remoteControl)\//.test(method) ||
        /error|warning|permission|approval/i.test(method)) held('UNSUPPORTED_EVENT');
    // Non-authoritative future metadata can never establish completion or run
    // an action. Every server request is rejected at the framing boundary.
  }
  generate(input, signal) {
    let request;
    try {
      request = snapshotModelRequest(input);
      if (!(signal instanceof AbortSignal)) held('INVALID_OPTIONS');
      if (signal.aborted) held('ABORTED');
      if (this.closed || this.channel.failure) held('SESSION_CLOSED');
      if (this.seenCalls.has(request.callId) || this.seenCalls.size >= 1000) held('CALL_REPLAY');
      this.seenCalls.add(request.callId);
    } catch (error) { return Promise.reject(error instanceof ModelSessionError ? error : new ModelSessionError('INVALID_REQUEST')); }
    const operation = this.queue.then(() => this.runCall(request, signal));
    this.queue = operation.catch(() => {});
    const cancelled = deferred(), abort = () => {
      if (this.active?.request.callId !== request.callId) cancelled.reject(new ModelSessionError('ABORTED'));
    };
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    return Promise.race([operation, cancelled.promise]).finally(() => signal.removeEventListener('abort', abort));
  }
  async runCall(request, signal) {
    if (signal.aborted) held('ABORTED');
    if (this.closed || this.channel.failure) held('SESSION_CLOSED');
    const state = { request, completion: deferred(), cancellation: deferred(), early: [], aborted: false };
    this.active = state; this.channel.resetBudget();
    const abort = () => { state.aborted = true; state.abortError = new ModelSessionError('ABORTED'); state.cancellation.reject(state.abortError); };
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    const turnTimer = setTimeout(() => { state.aborted = true; state.abortError = new ModelSessionError('TIMEOUT'); state.cancellation.reject(state.abortError); }, this.options.turnTimeoutMs);
    const wait = task => {
      if (state.aborted || signal.aborted) return Promise.reject(state.abortError ?? new ModelSessionError('ABORTED'));
      return Promise.race([task(), state.cancellation.promise]);
    };
    let result, failure, workspace;
    try {
      const proof = await wait(() => this.options.permissionCanary({ executable: this.options.executable, sourceEnv: this.options.sourceEnv }));
      verifyProof(proof, this.executableSha256);
      if (await wait(() => canaryExecutableSha256(this.options.executable)) !== this.executableSha256) held('RUNTIME_CHANGED');
      await wait(() => this.account()); await wait(() => this.model());
      const effort = request.reasoningEffort ?? this.modelInfo.defaultEffort;
      if (!this.modelInfo.efforts.has(effort)) held('UNSUPPORTED_CAPABILITY');
      workspace = await mkdtemp(join(this.root, 'call-'));
      workspace = await realpath(workspace);
      // This text-only port has no environment or file inputs. Explicit empty
      // environments materialize no runtime roots in the native protocol; do
      // not request contradictory roots or enable an environment to echo them.
      const source = await wait(() => this.channel.rpc('thread/start', { model: MODEL, modelProvider: 'openai', allowProviderModelFallback: false,
        cwd: workspace, runtimeWorkspaceRoots: [], permissions: CANARY_PROFILE, ephemeral: true, approvalPolicy: 'never',
        dynamicTools: [], environments: [], selectedCapabilityRoots: [], baseInstructions: request.system,
        developerInstructions: BOUNDARY + (request.responseFormat === 'json' && !request.responseSchema ? ' Return exactly one valid JSON object, with no surrounding prose.' : ''),
        serviceName: 'corely_local_synthetic_model', config: { model_reasoning_effort: effort, ...(request.verbosity ? { model_verbosity: request.verbosity } : {}) } }));
      const id = source?.thread?.id;
      if (typeof id !== 'string' || !id || this.seenThreads.has(id)) held('THREAD_MISMATCH');
      state.threadId = id; this.seenThreads.add(id);
      if (source.model !== MODEL || source.modelProvider !== 'openai' || source.thread.modelProvider !== 'openai' || source.thread.ephemeral !== true) held('MODEL_CHANGED');
      if (source.activePermissionProfile?.id !== CANARY_PROFILE || source.activePermissionProfile.extends != null ||
          source.sandbox?.type !== 'readOnly' || source.sandbox.networkAccess !== false || source.cwd !== workspace ||
          !Array.isArray(source.runtimeWorkspaceRoots) || source.runtimeWorkspaceRoots.length !== 0 || source.approvalPolicy !== 'never') held('SANDBOX_UNVERIFIED');
      if (!Array.isArray(source.instructionSources) || source.instructionSources.length) held('UNEXPECTED_INSTRUCTIONS');
      for (const event of state.early.splice(0)) this.notification(...event);
      const started = await wait(() => { state.turnRequested = true; return this.channel.rpc('turn/start', { threadId: id, input: [{ type: 'text', text: request.user }], model: MODEL,
        effort, approvalPolicy: 'never', permissions: CANARY_PROFILE, runtimeWorkspaceRoots: [], environments: [],
        ...(request.responseSchema ? { outputSchema: request.responseSchema } : {}) }); });
      if (typeof started?.turn?.id !== 'string' || (state.turnId && started.turn.id !== state.turnId)) held('TURN_MISMATCH');
      state.turnId ??= started.turn.id;
      await wait(() => state.completion.promise);
      if (this.channel.failure) throw this.channel.failure;
      await wait(() => this.account());
      if (await wait(() => canaryExecutableSha256(this.options.executable)) !== this.executableSha256) held('RUNTIME_CHANGED');
      const bound = { accountAlias: this.options.account, authMode: 'managed_chatgpt', accountVerified: true, model: MODEL,
        callId: request.callId, inputSha256: request.inputSha256, schemaSha256: request.schemaSha256 };
      if (state.nativeQuota && state.terminal === 'failed') result = Object.freeze({ ...bound, status: 'quota_exhausted', code: 'QUOTA_EXHAUSTED', authenticated: true });
      else {
        if (state.nativeQuota) held('TURN_FAILED');
        validateOutput(state.final.text, request);
        result = Object.freeze({ ...bound, status: 'success', completionStatus: 'completed', text: state.final.text, usage: state.usage });
      }
    } catch (error) { failure = error instanceof ModelSessionError ? error : new ModelSessionError('PROTOCOL_ERROR'); }
    finally {
      clearTimeout(turnTimer); signal.removeEventListener('abort', abort);
      try {
        if (state.aborted && this.channel.pending.size && !this.channel.failure) held('CLEANUP_FAILED');
        if (state.threadId && !this.channel.failure) {
          if (!state.terminal && state.turnRequested) {
            if (!state.turnId) held('CLEANUP_FAILED');
            await this.channel.rpc('turn/interrupt', { threadId: state.threadId, turnId: state.turnId }, this.options.cleanupTimeoutMs);
            let timer;
            try { await Promise.race([state.completion.promise, new Promise((resolve, reject) => { timer = setTimeout(() => reject(new ModelSessionError('CLEANUP_FAILED')), this.options.cleanupTimeoutMs); })]); }
            finally { clearTimeout(timer); }
            if (state.terminal !== 'interrupted') held('CLEANUP_FAILED');
          }
          const unsubscribed = await this.channel.rpc('thread/unsubscribe', { threadId: state.threadId }, this.options.cleanupTimeoutMs);
          if (!['unsubscribed', 'notLoaded'].includes(unsubscribed?.status)) held('CLEANUP_FAILED');
        } else if (state.turnRequested && !this.channel.failure) held('CLEANUP_FAILED');
      } catch { failure = new ModelSessionError('CLEANUP_FAILED'); }
      failure ??= this.channel.failure;
      this.active = undefined;
      if (workspace) {
        try { await rm(workspace, { recursive: true, force: true }); }
        catch { failure = new ModelSessionError('CLEANUP_FAILED'); }
      }
      if (failure && !['ABORTED', 'TIMEOUT', 'INVALID_STRUCTURED_OUTPUT', 'INVALID_OUTPUT', 'UNSUPPORTED_CAPABILITY'].includes(failure.code)) {
        await this.close().catch(() => {});
      }
    }
    if (failure) throw failure;
    if (signal.aborted) held('ABORTED');
    return result;
  }
  close() {
    if (this.closing) return this.closing;
    this.closed = true;
    this.active?.cancellation.reject(new ModelSessionError('SESSION_CLOSED'));
    this.closing = (async () => {
      let failed = false;
      try { await this.channel.close(); } catch { failed = true; }
      try { await rm(this.root, { recursive: true, force: true }); } catch { failed = true; }
      if (failed) held('CLEANUP_FAILED');
    })();
    return this.closing;
  }
}

export async function createManagedModelSession({ executable, account, login = false, onLogin,
  sourceEnv = process.env, permissionCanary = runPermissionsCanary, rpcTimeoutMs = 15000, turnTimeoutMs = 60000,
  cleanupTimeoutMs = 2000, loginTimeoutMs = 300000 } = {}) {
  // Check the real parent environment as well as supplied inputs before the
  // environment allowlist strips deployment metadata. A "local" sourceEnv or
  // caller-declared approval cannot hide a recognizable hosted parent process.
  try {
    if ([process.env, sourceEnv].some(env => env && typeof env === 'object' &&
        HOSTED_EXECUTION_MARKERS.some(key => key in env))) held('HOSTED_EXECUTION_REJECTED');
  } catch (error) {
    if (error instanceof ModelSessionError) throw error;
    held('INVALID_OPTIONS');
  }
  if (typeof executable !== 'string' || !isAbsolute(executable) || !Object.hasOwn(HARNESS_ACCOUNTS, account) || typeof login !== 'boolean' ||
      (login && typeof onLogin !== 'function') || typeof permissionCanary !== 'function' || !sourceEnv || typeof sourceEnv !== 'object' ||
      [rpcTimeoutMs, turnTimeoutMs, cleanupTimeoutMs, loginTimeoutMs].some(value => !Number.isSafeInteger(value) || value <= 0) ||
      rpcTimeoutMs > 15000 || turnTimeoutMs > 60000 || cleanupTimeoutMs > 5000 || loginTimeoutMs > 300000) held('INVALID_OPTIONS');
  sourceEnv = Object.freeze(Object.fromEntries(['LANG', 'TZ'].filter(key => typeof sourceEnv[key] === 'string' &&
    sourceEnv[key].length <= 100 && !sourceEnv[key].includes('\0')).map(key => [key, sourceEnv[key]])));
  let hash;
  try {
    hash = await canaryExecutableSha256(executable);
    verifyProof(await permissionCanary({ executable, sourceEnv }), hash);
    if (await canaryExecutableSha256(executable) !== hash) held('RUNTIME_CHANGED');
  } catch (error) { throw error instanceof ModelSessionError ? error : new ModelSessionError('SANDBOX_UNVERIFIED'); }
  let root, channel, session;
  try {
    root = await mkdtemp(join(tmpdir(), 'corely-managed-model-'));
    root = await realpath(root);
    const home = join(root, 'empty-home'), codexHome = join(root, 'empty-codex-home'), temporary = join(root, 'temporary'), cwd = join(root, 'empty-workspace');
    for (const path of [home, codexHome, temporary, cwd]) await mkdir(path, { mode: 0o700 });
    const env = { HOME: home, CODEX_HOME: codexHome, TMPDIR: temporary, PATH: '/usr/bin:/bin' };
    for (const key of ['LANG', 'TZ']) if (typeof sourceEnv[key] === 'string' && sourceEnv[key].length <= 100 && !sourceEnv[key].includes('\0')) env[key] = sourceEnv[key];
    const args = ['app-server', '--listen', 'stdio://', '-c', 'model_provider="openai"', '-c', 'forced_login_method="chatgpt"',
      '-c', 'cli_auth_credentials_store="ephemeral"', '-c', 'web_search="disabled"', ...DISABLED.flatMap(name => ['--disable', name]),
      ...canaryProfileOverrides().flatMap(value => ['-c', value])];
    channel = new OfficialChannel(executable, args, env, cwd, rpcTimeoutMs);
    session = new ManagedModelSession({ executable, account, sourceEnv, permissionCanary, turnTimeoutMs, cleanupTimeoutMs }, root, channel, hash);
    await channel.rpc('initialize', { clientInfo: { name: 'corely_managed_model_port', version: MODEL_SESSION_VERSION }, capabilities: { experimentalApi: true } });
    channel.child.stdin.write(`${JSON.stringify({ method: 'initialized', params: {} })}\n`);
    const initial = await channel.rpc('account/read', { refreshToken: false });
    if (initial?.account) session.plan = validateIdentity(initial, account);
    if (!initial?.account) {
      if (!login) held('AUTH_REQUIRED');
      const completed = channel.wait('account/login/completed', loginTimeoutMs);
      const ceremony = await channel.rpc('account/login/start', { type: 'chatgpt', useHostedLoginSuccessPage: true, appBrand: 'codex' });
      let url;
      try { url = new URL(ceremony.authUrl); } catch { held('LOGIN_FAILED'); }
      if (ceremony.type !== 'chatgpt' || typeof ceremony.loginId !== 'string' || !ceremony.loginId ||
          !['https://auth.openai.com', 'https://chatgpt.com'].includes(url.origin) || url.username || url.password || url.href.length > 8192) held('LOGIN_FAILED');
      try { await Promise.race([Promise.resolve().then(() => onLogin(url.href)), completed]); }
      catch (error) { if (error instanceof ModelSessionError) throw error; held('LOGIN_FAILED'); }
      const done = await completed;
      if (done?.success !== true || done.loginId !== ceremony.loginId) held('LOGIN_FAILED');
    }
    await session.account(); await session.model();
    if (channel.failure) throw channel.failure;
    const metadata = Object.freeze({ version: MODEL_SESSION_VERSION, executableSha256: hash, accountAlias: account,
      authMode: 'managed_chatgpt', model: MODEL, planType: session.plan, permissionProfile: CANARY_PROFILE,
      exactPlanDebitAttested: false, apiFallbackUsed: false });
    return Object.freeze({ capabilities: CAPABILITIES, metadata, generate: session.generate.bind(session), close: session.close.bind(session) });
  } catch (error) {
    if (session) await session.close().catch(() => {});
    else {
      if (channel) await channel.close().catch(() => {});
      if (root) await rm(root, { recursive: true, force: true }).catch(() => {});
    }
    throw error instanceof ModelSessionError ? error : new ModelSessionError('PROTOCOL_ERROR');
  }
}
