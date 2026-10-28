// Private, owner-operated synthetic Corely model port. No listener, API key,
// native credential cache, tool execution, sending or learning capability.
import { randomUUID } from 'node:crypto';
import { MODEL, RESOURCE, ProbeError, publicJson, selectExactModel, consumePlanTextStream,
  inferenceFailureDiagnostic } from './siwc-local-runtime.mjs';
import { snapshotModelRequest, validateModelOutput } from './corely-model-contract.mjs';

/** Preserve the complete prompt and strict output contract. SIWC uses the
 * public Responses endpoint, not Chat Completions or a ChatGPT backend proxy.
 * Unsupported API parameters are not forwarded or silently substituted. */
export function corelyPlanPayload(input, accountAlias) {
  const request = snapshotModelRequest(input);
  if (accountAlias !== undefined && !['info', 'eason'].includes(accountAlias)) throw new ProbeError('MODEL_PORT_INVALID');
  const text = {};
  if (request.responseSchema) text.format = { type: 'json_schema', name: 'corely_model_output', strict: true, schema: request.responseSchema };
  else if (request.responseFormat === 'json') text.format = { type: 'json_object' };
  if (request.verbosity) text.verbosity = request.verbosity;
  if (request.promptCache && accountAlias === undefined) throw new ProbeError('MODEL_PORT_INVALID');
  // SIWC uses one conservative wire profile for every account and purpose.
  // Validated optimization hints remain bound to the original request/hash,
  // but optional API cache fields are not forwarded on this plan route. Keep
  // every prompt byte and the independent output/review contracts unchanged.
  return Object.freeze({ request, payload: Object.freeze({ model: MODEL, instructions: request.system,
    input: [{ role: 'user', content: request.user }],
    store: false, stream: true,
    ...(Object.keys(text).length ? { text } : {}),
    ...(request.reasoningEffort ? { reasoning: { effort: request.reasoningEffort } } : {}) }) });
}

function whileActive(work, signal) {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(signal.reason); };
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(work).then(value => { signal.removeEventListener('abort', abort); resolve(value); },
      error => { signal.removeEventListener('abort', abort); reject(error); });
  });
}

/** Called under the selected application's account lease after signed SIWC
 * enrollment/refresh validation. Scope flags are a wire binding, not the
 * authority to read a customer: the future Corely producer must separately
 * enforce server-owned synthetic provenance before creating any such job. */
export async function runCorelyPlanRequest(session, input, fetchImpl = globalThis.fetch, signal) {
  const { request, payload } = corelyPlanPayload(input, session?.alias);
  if (!(signal instanceof AbortSignal) || typeof fetchImpl !== 'function') throw new ProbeError('MODEL_PORT_INVALID');
  signal.throwIfAborted();
  if (!['info', 'eason'].includes(session?.alias) || session?.planScopeGranted !== true || session?.accountMatchesExpected !== true ||
      typeof session.accessToken !== 'string' || !/^[\x21-\x7e]{1,65536}$/.test(session.accessToken) ||
      !Number.isSafeInteger(session.expiresAt) || session.expiresAt <= Date.now()) throw new ProbeError('SESSION_NOT_ELIGIBLE');
  const deadline = AbortSignal.timeout(60_000), active = AbortSignal.any([signal, deadline]);
  const headers = { Authorization: `Bearer ${session.accessToken}` }, clientRequestId = randomUUID();
  const bound = { accountAlias: session.alias, authMode: 'siwc_plan', accountVerified: true, model: MODEL,
    callId: request.callId, inputSha256: request.inputSha256, schemaSha256: request.schemaSha256 };
  let response;
  try {
    const catalog = await whileActive(publicJson(`${RESOURCE}/models`, { headers }, fetchImpl, active), active);
    selectExactModel(catalog); active.throwIfAborted();
    if (session.expiresAt <= Date.now()) throw new ProbeError('SESSION_NOT_ELIGIBLE');
    response = await whileActive(Promise.resolve().then(() => {
      active.throwIfAborted();
      return fetchImpl(`${RESOURCE}/responses`, { method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store',
        headers: { ...headers, 'Content-Type': 'application/json', Accept: 'text/event-stream', 'X-Client-Request-Id': clientRequestId },
        body: JSON.stringify(payload), signal: active });
    }), active);
    if (!response || response.redirected || (response.url && response.url !== `${RESOURCE}/responses`)) throw new ProbeError('INFERENCE_RESPONSE_INVALID');
    if (!response.ok) throw new ProbeError(`INFERENCE_HTTP_${response.status}`,
      await whileActive(inferenceFailureDiagnostic(response), active));
    const media = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
    if (media && media !== 'text/event-stream') throw new ProbeError('INVALID_STREAM_CONTENT_TYPE',
      await whileActive(inferenceFailureDiagnostic(response), active));
    const receipt = await whileActive(consumePlanTextStream(response.body, active), active);
    active.throwIfAborted();
    validateModelOutput(receipt.text, request);
    return Object.freeze({ ...bound, status: 'success', completionStatus: 'completed', text: receipt.text,
      usage: Object.freeze({ inputTokens: receipt.usage.inputTokens, outputTokens: receipt.usage.outputTokens,
        cachedInputTokens: receipt.cachedInputTokens }) });
  } catch (error) {
    if (active.aborted) throw new ProbeError(deadline.aborted ? 'MODEL_PORT_TIMEOUT' : 'SESSION_OPERATION_ABORTED');
    // A quota receipt is emitted only after this account's authenticated
    // catalog has passed and the official inference route reports exhaustion.
    if (error instanceof ProbeError && error.diagnostic?.errorCode === 'subscription_sharing_usage_limit_exceeded') {
      return Object.freeze({ ...bound, status: 'quota_exhausted', code: 'QUOTA_EXHAUSTED', authenticated: true });
    }
    if (error instanceof ProbeError) throw error;
    if (['INVALID_OUTPUT', 'INVALID_STRUCTURED_OUTPUT'].includes(error?.code)) throw new ProbeError(error.code);
    throw new ProbeError('MODEL_PORT_UNAVAILABLE');
  } finally {
    // If a provider stream ignores cancellation, return promptly but never
    // interpret its late content as a result or retry an uncertain model call.
    if (active.aborted && response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
  }
}

/** In-process ports only. The companion's authenticated job transport and the
 * Corely bootstrap must be wired separately; importing this installs nothing. */
export function createSiwcModelTransports(sessions) {
  if (!sessions || typeof sessions.generate !== 'function') throw new ProbeError('MODEL_PORT_INVALID');
  const port = alias => Object.freeze({ authMode: 'siwc_plan', capabilities: Object.freeze({ text: true, structuredJson: true, images: false }),
    generate: (request, signal) => sessions.generate(alias, request, signal) });
  return Object.freeze({ info: port('info'), eason: port('eason') });
}

/** Ephemeral normal-login test port. The grant stays in this app's closure;
 * ending its owning OAuth attempt aborts every retained port reference. */
export function createTransientSiwcModelPort(session, fetchImpl, lifetime) {
  if (!(lifetime instanceof AbortSignal) || !['info', 'eason'].includes(session?.alias) ||
      session.planScopeGranted !== true || session.accountMatchesExpected !== true) throw new ProbeError('MODEL_PORT_INVALID');
  const seen = new Set();
  let retained = Object.freeze({ alias: session.alias, accessToken: session.accessToken, expiresAt: session.expiresAt,
    planScopeGranted: true, accountMatchesExpected: true });
  const discard = () => { retained = undefined; };
  lifetime.addEventListener('abort', discard, { once: true });
  if (lifetime.aborted) discard();
  return Object.freeze({ authMode: 'siwc_plan', capabilities: Object.freeze({ text: true, structuredJson: true, images: false }),
    generate(input, signal) {
      if (!(signal instanceof AbortSignal)) return Promise.reject(new ProbeError('MODEL_PORT_INVALID'));
      if (!retained || signal.aborted) return Promise.reject(new ProbeError('SESSION_OPERATION_ABORTED'));
      const request = snapshotModelRequest(input);
      if (seen.has(request.callId) || seen.size >= 50) return Promise.reject(new ProbeError('MODEL_CALL_REPLAY_OR_CAPACITY'));
      seen.add(request.callId);
      return runCorelyPlanRequest(retained, request, fetchImpl, AbortSignal.any([signal, lifetime]));
    } });
}
