#!/usr/bin/env node
// Local owner-operated Codex harness smoke test, NOT a public inference gateway.
// Codex owns its normal sign-in lifecycle. This program never reads auth caches,
// imports tokens, accepts arbitrary prompts, exposes HTTP, or enables fallback.
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const MODEL = 'gpt-6.1-sol';
export const EXPECTED_ACCOUNT = 'info@moztech.cc';
export const EXPECTED_OUTPUT = 'Corely Codex harness probe OK.';
const PROMPT = `This is a local, owner-operated synthetic integration test. Do not inspect files, invoke tools, access websites, modify anything, or use prior conversation history. Reply with exactly: ${EXPECTED_OUTPUT}`;
const ERRORS = new Set(['INVALID_OPTIONS', 'UNSAFE_HOME', 'SPAWN_FAILED', 'PROTOCOL_ERROR', 'RPC_FAILED', 'TIMEOUT',
  'OUTPUT_LIMIT', 'AUTH_REQUIRED', 'AUTH_MODE_REJECTED', 'WRONG_ACCOUNT', 'PLAN_UNVERIFIED', 'MODEL_UNAVAILABLE',
  'TOOL_USE_REJECTED', 'TURN_FAILED', 'INVALID_OUTPUT', 'INCOMPLETE_TURN', 'PROCESS_FAILED', 'INVALID_USAGE',
  'LOGIN_FAILED', 'UNEXPECTED_INSTRUCTIONS', 'MODEL_CHANGED', 'SANDBOX_UNVERIFIED',
  'THREAD_MISMATCH', 'TURN_MISMATCH', 'INPUT_MISMATCH', 'UNSUPPORTED_EVENT']);
export class HarnessError extends Error {
  constructor(code, diagnostic) {
    super(ERRORS.has(code) ? code : 'PROTOCOL_ERROR'); this.code = this.message;
    if (diagnostic && ['initialize', 'account/read', 'account/login/start', 'model/list', 'thread/start', 'turn/start'].includes(diagnostic.method)) {
      this.diagnostic = Object.freeze({ method: diagnostic.method,
        rpcCode: Number.isSafeInteger(diagnostic.rpcCode) ? diagnostic.rpcCode : null,
        reason: ['EXPERIMENTAL_API_REQUIRED', 'INVALID_PARAMS', 'OTHER'].includes(diagnostic.reason) ? diagnostic.reason : 'OTHER' });
    }
  }
}

// Deliberately do not inherit API keys, access tokens, provider URLs, proxies,
// NODE_OPTIONS, config overrides, or remote-control settings from the caller.
export function buildChildEnv(source, codexHome) {
  const env = {};
  for (const key of ['HOME', 'PATH', 'TMPDIR', 'LANG', 'TZ']) {
    if (typeof source[key] === 'string') env[key] = source[key];
  }
  env.CODEX_HOME = codexHome;
  return env;
}

export function verifyAccount(result) {
  const account = result?.account;
  if (!account) throw new HarnessError('AUTH_REQUIRED');
  if (account.type !== 'chatgpt' || result.requiresOpenaiAuth !== true) throw new HarnessError('AUTH_MODE_REJECTED');
  if (account.email !== EXPECTED_ACCOUNT) throw new HarnessError('WRONG_ACCOUNT');
  if (!['plus', 'pro', 'business', 'enterprise', 'edu'].includes(account.planType)) throw new HarnessError('PLAN_UNVERIFIED');
  return Object.freeze({ authMode: 'chatgpt', expectedAccountMatch: true, planType: account.planType });
}

export function verifyModel(result) {
  if (!Array.isArray(result?.data) || !result.data.some(row => row?.model === MODEL && row.hidden !== true)) {
    throw new HarnessError('MODEL_UNAVAILABLE');
  }
  return MODEL;
}

export function createExecAccumulator() {
  let thread = false, started = false, completed = false, final = false, usage;
  return {
    consume(event) {
      if (!event || typeof event !== 'object' || completed) throw new HarnessError('PROTOCOL_ERROR');
      switch (event.type) {
        case 'thread.started':
          if (thread || started || typeof event.thread_id !== 'string' || !event.thread_id) throw new HarnessError('PROTOCOL_ERROR');
          thread = true; break;
        case 'turn.started':
          if (!thread || started) throw new HarnessError('PROTOCOL_ERROR');
          started = true; break;
        case 'item.started': case 'item.updated': case 'item.completed': {
          if (!started || !event.item) throw new HarnessError('PROTOCOL_ERROR');
          if (!['reasoning', 'agent_message'].includes(event.item.type)) throw new HarnessError('TOOL_USE_REJECTED');
          if (event.item.type === 'agent_message' && event.type === 'item.completed') {
            if (final || event.item.text !== EXPECTED_OUTPUT) throw new HarnessError('INVALID_OUTPUT');
            final = true;
          }
          break;
        }
        case 'turn.completed': {
          if (!started || !final) throw new HarnessError('INCOMPLETE_TURN');
          const value = event.usage;
          if (!value || !['input_tokens', 'output_tokens'].every(key => Number.isSafeInteger(value[key]) && value[key] >= 0)) {
            throw new HarnessError('INVALID_USAGE');
          }
          usage = Object.freeze({ inputTokens: value.input_tokens, outputTokens: value.output_tokens });
          completed = true; break;
        }
        case 'error': case 'turn.failed': throw new HarnessError('TURN_FAILED');
        default: throw new HarnessError('PROTOCOL_ERROR');
      }
    },
    finish(exitCode) {
      if (exitCode !== 0) throw new HarnessError('PROCESS_FAILED');
      if (!completed || !final) throw new HarnessError('INCOMPLETE_TURN');
      return Object.freeze({ model: MODEL, generationCompleted: true, outputMatched: true, usage });
    },
  };
}

const disabled = ['shell_tool', 'unified_exec', 'apps', 'plugins', 'hooks', 'browser_use', 'browser_use_external',
  'computer_use', 'image_generation', 'code_mode_host', 'multi_agent', 'multi_agent_v2', 'memories', 'chronicle',
  'skill_search', 'view_image', 'sleep_tool', 'in_app_browser', 'unbounded_connection_retries'];

// Authentication, model discovery, thread and turn all use ONE official process.
// No custom API/base URL: the official harness owns its native ChatGPT route.
async function runSession(executable, env, cwd, { login, runSynthetic, onLogin }) {
  const args = ['app-server', '--listen', 'stdio://', '-c', 'model_provider="openai"',
    '-c', 'forced_login_method="chatgpt"', '-c', 'cli_auth_credentials_store="ephemeral"',
    '-c', 'web_search="disabled"', '-c', 'model_reasoning_effort="low"',
    ...disabled.flatMap(name => ['--disable', name])];
  const child = spawn(executable, args,
    { cwd, env, stdio: ['pipe', 'pipe', 'ignore'] });
  let sequence = 0, buffer = '', bytes = 0, closed = false;
  const pending = new Map();
  const waiters = new Map();
  let generationHandler;
  let terminalError;
  const fail = error => {
    terminalError ??= error;
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(terminalError); }
    for (const item of waiters.values()) { clearTimeout(item.timer); item.reject(terminalError); }
    pending.clear(); waiters.clear(); child.kill('SIGTERM');
  };
  child.on('error', () => fail(new HarnessError('SPAWN_FAILED')));
  child.on('close', () => { closed = true; if (pending.size || waiters.size) fail(new HarnessError('PROCESS_FAILED')); });
  child.stdin.on('error', () => fail(new HarnessError('PROCESS_FAILED')));
  child.stdout.on('data', chunk => {
    bytes += chunk.length;
    if (bytes > 1024 * 1024) return fail(new HarnessError('OUTPUT_LIMIT'));
    buffer += chunk.toString('utf8');
    while (buffer.includes('\n')) {
      const end = buffer.indexOf('\n');
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { return fail(new HarnessError('PROTOCOL_ERROR')); }
      // Never return credentials, raw errors, log lines, or auth URLs.
      if (msg.method && msg.id !== undefined) return fail(new HarnessError('TOOL_USE_REJECTED'));
      if (msg.id === undefined) {
        const waiter = waiters.get(msg.method);
        if (waiter) { clearTimeout(waiter.timer); waiters.delete(msg.method); waiter.resolve(msg.params); }
        try { generationHandler?.(msg); }
        catch (error) { return fail(error instanceof HarnessError ? error : new HarnessError('PROTOCOL_ERROR')); }
        continue;
      }
      const item = pending.get(msg.id);
      if (!item) return fail(new HarnessError('PROTOCOL_ERROR'));
      clearTimeout(item.timer); pending.delete(msg.id);
      if (msg.error || !Object.hasOwn(msg, 'result')) item.reject(new HarnessError('RPC_FAILED', {
        method: item.method, rpcCode: msg.error?.code,
        reason: typeof msg.error?.message === 'string' && msg.error.message.includes('requires experimentalApi capability') ? 'EXPERIMENTAL_API_REQUIRED' : msg.error?.code === -32602 ? 'INVALID_PARAMS' : 'OTHER',
      }));
      else item.resolve(msg.result);
    }
  });
  const rpc = (method, params) => new Promise((resolveCall, reject) => {
    if (terminalError || closed) return reject(terminalError ?? new HarnessError('PROCESS_FAILED'));
    const id = ++sequence;
    const timer = setTimeout(() => fail(new HarnessError('TIMEOUT')), 15000);
    pending.set(id, { resolve: resolveCall, reject, timer, method });
    child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
  });
  const wait = (method, timeout) => new Promise((resolveCall, reject) => {
    if (terminalError || closed) return reject(terminalError ?? new HarnessError('PROCESS_FAILED'));
    const timer = setTimeout(() => fail(new HarnessError('TIMEOUT')), timeout);
    waiters.set(method, { resolve: resolveCall, reject, timer });
  });
  try {
    await rpc('initialize', { clientInfo: { name: 'corely_local_harness_pilot', title: 'Corely local synthetic harness pilot', version: '0.1.0' } });
    child.stdin.write(`${JSON.stringify({ method: 'initialized', params: {} })}\n`);
    const initial = await rpc('account/read', { refreshToken: false });
    if (!initial.account) {
      if (!login) throw new HarnessError('AUTH_REQUIRED');
      const completed = wait('account/login/completed', 300000);
      // Attach rejection immediately to avoid an unhandled rejection on RPC error.
      completed.catch(() => {});
      const ceremony = await rpc('account/login/start', { type: 'chatgpt', useHostedLoginSuccessPage: true, appBrand: 'codex' });
      let url;
      try { url = new URL(ceremony.authUrl); } catch { throw new HarnessError('LOGIN_FAILED'); }
      if (ceremony.type !== 'chatgpt' || !['https://auth.openai.com', 'https://chatgpt.com'].includes(url.origin) ||
          url.username || url.password) throw new HarnessError('LOGIN_FAILED');
      await onLogin(url.href);
      const result = await completed;
      if (result?.success !== true || result.loginId !== ceremony.loginId) throw new HarnessError('LOGIN_FAILED');
    }
    const identity = verifyAccount(await rpc('account/read', { refreshToken: false }));
    verifyModel(await rpc('model/list', { includeHidden: false, limit: 100 }));
    if (!runSynthetic) return { status: 'PREFLIGHT_PASSED', ...identity, model: MODEL, modelRequestMade: false, apiFallbackUsed: false };
    // ThreadStartParams.SandboxMode uses kebab-case in the installed protocol;
    // TurnStartParams.SandboxPolicy below uses a camel-case tagged union.
    const source = await rpc('thread/start', { model: MODEL, cwd, ephemeral: true, approvalPolicy: 'never', sandbox: 'read-only',
      serviceName: 'corely_local_synthetic', developerInstructions: PROMPT });
    const threadId = source?.thread?.id;
    if (source.model !== MODEL || source?.thread?.modelProvider !== 'openai' || source?.thread?.ephemeral !== true ||
        typeof threadId !== 'string' || !threadId) throw new HarnessError('MODEL_CHANGED');
    if (source.sandbox?.type !== 'readOnly' || source.sandbox.networkAccess !== false) throw new HarnessError('SANDBOX_UNVERIFIED');
    if (!Array.isArray(source.instructionSources) || source.instructionSources.length) throw new HarnessError('UNEXPECTED_INSTRUCTIONS');
    const accumulator = createExecAccumulator();
    accumulator.consume({ type: 'thread.started', thread_id: threadId });
    let turnId, usage, turnFinished = false;
    const completed = wait('turn/completed', 90000);
    completed.catch(() => {});
    generationHandler = msg => {
      const p = msg.params;
      if (p?.threadId !== undefined && p.threadId !== threadId) throw new HarnessError('THREAD_MISMATCH');
      if (msg.method === 'thread/started') {
        if (p?.thread?.id !== threadId) throw new HarnessError('PROTOCOL_ERROR');
        return;
      }
      if (msg.method === 'account/updated') {
        if (p?.authMode !== 'chatgpt' || (p.planType !== undefined && p.planType !== identity.planType)) {
          throw new HarnessError('AUTH_MODE_REJECTED');
        }
        return;
      }
      if (msg.method === 'turn/started') {
        if (turnId || typeof p?.turn?.id !== 'string') throw new HarnessError('PROTOCOL_ERROR');
        turnId = p.turn.id;
        accumulator.consume({ type: 'turn.started' }); return;
      }
      if (p?.turnId !== undefined && p.turnId !== turnId) throw new HarnessError('TURN_MISMATCH');
      if (msg.method === 'item/started' || msg.method === 'item/completed') {
        if (p?.item?.type === 'userMessage') {
          if (p.item.content?.length !== 1 || p.item.content[0]?.type !== 'text' || p.item.content[0].text !== PROMPT) {
            throw new HarnessError('INPUT_MISMATCH');
          }
          return;
        }
        const type = { agentMessage: 'agent_message', reasoning: 'reasoning' }[p?.item?.type];
        if (!type) throw new HarnessError('TOOL_USE_REJECTED');
        accumulator.consume({ type: msg.method === 'item/started' ? 'item.started' : 'item.completed', item: { type, text: p.item.text } }); return;
      }
      if (msg.method === 'thread/tokenUsage/updated') {
        usage = p?.tokenUsage?.last; return;
      }
      if (msg.method === 'turn/completed') {
        if (p?.turn?.id !== turnId || p.turn.status !== 'completed' || p.turn.error) throw new HarnessError('TURN_FAILED');
        accumulator.consume({ type: 'turn.completed', usage: { input_tokens: usage?.inputTokens, output_tokens: usage?.outputTokens } });
        turnFinished = true; return;
      }
      if (['thread/status/changed', 'remoteControl/status/changed', 'account/rateLimits/updated', 'item/agentMessage/delta',
        'item/reasoning/summaryTextDelta', 'item/reasoning/summaryPartAdded', 'item/reasoning/textDelta'].includes(msg.method)) return;
      if (msg.method === 'model/rerouted') throw new HarnessError('MODEL_CHANGED');
      if (msg.method === 'error') throw new HarnessError('TURN_FAILED');
      if (typeof msg.method !== 'string' || /^(item|account|auth|model|modelProvider|hook|mcpServer|app|process|command|fs|remoteControl)\//.test(msg.method) ||
          /error|warning|permission|approval/i.test(msg.method)) throw new HarnessError('UNSUPPORTED_EVENT');
      // JSON-RPC notifications may grow across official runtime releases.
      // Unknown metadata is never accepted as evidence or executed. Only the
      // strict known item/completion contract above can establish success;
      // every server-requested action is rejected before this handler.
      return;
    };
    // Inherit the verified read-only/no-network thread policy. This installed
    // protocol does not support the newer ReadOnlyAccess override. The fixed
    // trusted smoke has no file/command tools or arbitrary customer input.
    const started = await rpc('turn/start', { threadId, input: [{ type: 'text', text: PROMPT }], model: MODEL, effort: 'low',
      approvalPolicy: 'never' });
    if (turnId !== undefined && started?.turn?.id !== turnId) throw new HarnessError('PROTOCOL_ERROR');
    await completed;
    if (terminalError) throw terminalError;
    if (!turnFinished) throw new HarnessError('INCOMPLETE_TURN');
    generationHandler = undefined;
    const after = verifyAccount(await rpc('account/read', { refreshToken: false }));
    if (identity.planType !== after.planType) throw new HarnessError('PLAN_UNVERIFIED');
    return { status: 'SYNTHETIC_HARNESS_PASSED', ...identity, ...accumulator.finish(0), apiFallbackUsed: false,
      exactPlanDebitAttested: false, corelyConnected: false, sendingEnabled: false, learningEnabled: false };
  } finally {
    for (const item of pending.values()) clearTimeout(item.timer);
    for (const item of waiters.values()) clearTimeout(item.timer);
    child.stdin.end(); child.kill('SIGTERM');
    await new Promise(done => {
      if (closed) return done();
      const timer = setTimeout(() => { child.kill('SIGKILL'); done(); }, 2000);
      child.once('close', () => { clearTimeout(timer); done(); });
    });
  }
}

export async function runPilot({ executable, login = false, runSynthetic = false, sourceEnv = process.env, onLogin = async () => { throw new HarnessError('AUTH_REQUIRED'); } }) {
  if (!isAbsolute(executable)) throw new HarnessError('INVALID_OPTIONS');
  const root = await realpath(await mkdtemp(join(tmpdir(), 'corely-codex-harness-')));
  const cwd = join(root, 'workspace'), home = join(root, 'codex-home');
  await mkdir(cwd, { mode: 0o700 }); await mkdir(home, { mode: 0o700 });
  const env = buildChildEnv(sourceEnv, home);
  try {
    return await runSession(executable, env, cwd, { login, runSynthetic, onLogin });
  } finally { await rm(root, { recursive: true, force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  const valid = args.length >= 2 && args[0] === '--executable' && new Set(args.slice(2)).size === args.length - 2 &&
    args.slice(2).every(arg => ['--login', '--run-synthetic'].includes(arg));
  try {
    if (!valid) throw new HarnessError('INVALID_OPTIONS');
    const receipt = await runPilot({ executable: args[1], login: args.includes('--login'), runSynthetic: args.includes('--run-synthetic'),
      onLogin: async authUrl => { process.stdout.write(`${JSON.stringify({ status: 'NORMAL_CODEX_LOGIN_REQUIRED', authUrl })}\n`); } });
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ status: 'HARNESS_FAILED', code: error instanceof HarnessError ? error.code : 'PROTOCOL_ERROR',
      ...(error instanceof HarnessError && error.diagnostic ? { diagnostic: error.diagnostic } : {}), apiFallbackUsed: false })}\n`);
    process.exitCode = 1;
  }
}
