// Shared bounded model JSON contract. Structural validity is not admission:
// each port separately authorizes its own local synthetic or regression scope.
// It validates JSON only: no process, network, credentials or model execution.
import { createHash } from 'node:crypto';
const MODEL = 'gpt-6.1-sol';
export const LOCAL_ORIGINAL50_CORPUS_SHA256 = 'c895a50c382ef87751f00cca0899b1660a0f77eca7b5cb72a8fc139573aba5e3';
const MAX_BYTES = 1024 * 1024;
const REQUEST_KEYS = new Set(['version', 'callId', 'workload', 'purpose', 'model', 'scope', 'system', 'user', 'responseFormat',
  'responseSchema', 'image', 'reasoningEffort', 'verbosity', 'promptCache', 'inputSha256', 'schemaSha256']);
const WORKLOADS = new Set(['DECISION_LLM', 'REPLY_LLM', 'WEB_CHAT_VISION', 'MEDIA_IMAGE_ANALYSIS']);
const PURPOSES = new Set(['semantic_reply_review', 'semantic_evidence_selection', 'support_decision', 'reply_generation',
  'reply_repair', 'structured_output', 'text_generation', 'image_analysis']);
const SCHEMA_KEYS = new Set(['type', 'description', 'title', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const',
  'minItems', 'maxItems', 'minLength', 'maxLength', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'uniqueItems']);
const TYPES = new Set(['null', 'object', 'array', 'string', 'integer', 'number', 'boolean']);

export class ModelContractError extends Error {
  constructor(code) { super(code); this.name = 'ModelContractError'; this.code = code; }
}
const held = code => { throw new ModelContractError(code); };
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

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

export function validateModelOutput(text, request) {
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

function snapshotRequest(input, options) {
  // This opt-in is only a private in-process bootstrap capability. Ordinary
  // SIWC, VM and synthetic workers call without it and keep their old scope.
  const admission = options === undefined ? {} : copyCanonical(options);
  if (!admission || typeof admission !== 'object' || Array.isArray(admission) ||
      Object.keys(admission).some(key => key !== 'allowHistoricalRegression') ||
      (Object.hasOwn(admission, 'allowHistoricalRegression') && admission.allowHistoricalRegression !== true)) held('INVALID_REQUEST');
  const request = copyCanonical(input);
  if (!request || typeof request !== 'object' || Array.isArray(request) || Object.keys(request).some(key => !REQUEST_KEYS.has(key)) ||
      request.version !== 1 || request.model !== MODEL || typeof request.callId !== 'string' || !/^[A-Za-z0-9_-]{1,160}$/.test(request.callId) ||
      !WORKLOADS.has(request.workload) || !PURPOSES.has(request.purpose) || typeof request.system !== 'string' || !request.system.trim() ||
      typeof request.user !== 'string' || !request.user.trim() || (request.responseFormat !== undefined && request.responseFormat !== 'json') ||
      (request.verbosity !== undefined && request.verbosity !== 'low') ||
      (request.reasoningEffort !== undefined && (typeof request.reasoningEffort !== 'string' || !/^[a-z][a-z0-9_-]{0,31}$/.test(request.reasoningEffort)))) held('INVALID_REQUEST');
  const s = request.scope;
  if (!s || typeof s !== 'object' || Array.isArray(s) || s.tenantId !== 'moztech' || s.brandId !== 'moztech-test' ||
      typeof s.jobId !== 'string' || !/^[A-Za-z0-9_-]{1,160}$/.test(s.jobId)) held('SCOPE_NOT_ADMITTED');
  const synthetic = Object.keys(s).length === 4 && s.synthetic === true &&
    Object.keys(s).every(key => ['tenantId', 'brandId', 'synthetic', 'jobId'].includes(key));
  const historical = admission.allowHistoricalRegression === true && Object.keys(s).length === 5 &&
    s.dataClass === 'historical_regression' && s.corpusSha256 === LOCAL_ORIGINAL50_CORPUS_SHA256 &&
    Object.keys(s).every(key => ['tenantId', 'brandId', 'dataClass', 'corpusSha256', 'jobId'].includes(key));
  if (!synthetic && !historical) held('SCOPE_NOT_ADMITTED');
  if (Object.hasOwn(request, 'image')) held('UNSUPPORTED_CAPABILITY');
  if (Object.hasOwn(request, 'promptCache')) {
    const cache = request.promptCache, boundary = cache?.userPrefixChars;
    if (!cache || typeof cache !== 'object' || Array.isArray(cache) ||
        Object.keys(cache).some(key => !['key', 'userPrefixChars'].includes(key)) ||
        typeof cache.key !== 'string' || !/^support-[a-f0-9]{64}$/.test(cache.key) ||
        (Object.hasOwn(cache, 'userPrefixChars') && (!Number.isSafeInteger(boundary) || boundary <= 0 || boundary >= request.user.length ||
          (/[\uD800-\uDBFF]/u.test(request.user[boundary - 1]) && /[\uDC00-\uDFFF]/u.test(request.user[boundary]))))) held('INVALID_REQUEST');
  }
  if (request.responseSchema !== undefined && !supportsSchema(request.responseSchema)) held('UNSUPPORTED_CAPABILITY');
  const schemaHash = request.responseSchema === undefined ? null : digest(request.responseSchema);
  if (request.schemaSha256 !== schemaHash || !/^[a-f0-9]{64}$/.test(request.inputSha256 ?? '')) held('INPUT_MISMATCH');
  const content = Object.fromEntries(Object.entries(request).filter(([key]) => key !== 'inputSha256'));
  if (digest(content) !== request.inputSha256) held('INPUT_MISMATCH');
  return request;
}

export function snapshotModelRequest(input, options) {
  try { return snapshotRequest(input, options); }
  catch (error) { throw error instanceof ModelContractError ? error : new ModelContractError('INVALID_REQUEST'); }
}

/** One receipt contract shared by the private worker and its Corely router.
 * Credentials and provider error bodies are never part of a model result. */
export function snapshotModelResult(input, request, accountAlias, authMode) {
  const result = copyCanonical(input);
  if (!['info', 'eason'].includes(accountAlias) || !['managed_chatgpt', 'siwc_plan'].includes(authMode) ||
      !result || typeof result !== 'object' || Array.isArray(result) || result.accountAlias !== accountAlias ||
      result.authMode !== authMode || result.accountVerified !== true || result.model !== MODEL ||
      result.callId !== request.callId || result.inputSha256 !== request.inputSha256 || result.schemaSha256 !== request.schemaSha256) held('INVALID_RECEIPT');
  const keys = ['accountAlias', 'authMode', 'accountVerified', 'model', 'callId', 'inputSha256', 'schemaSha256', 'status'];
  if (result.status === 'quota_exhausted') {
    if (result.code !== 'QUOTA_EXHAUSTED' || result.authenticated !== true ||
        Object.keys(result).some(key => ![...keys, 'code', 'authenticated'].includes(key))) held('INVALID_RECEIPT');
    return result;
  }
  if (result.status !== 'success' || result.completionStatus !== 'completed' ||
      Object.keys(result).some(key => ![...keys, 'completionStatus', 'text', 'usage'].includes(key))) held('INVALID_RECEIPT');
  const usage = result.usage;
  if (!usage || typeof usage !== 'object' || Array.isArray(usage) ||
      Object.keys(usage).some(key => !['inputTokens', 'outputTokens', 'cachedInputTokens'].includes(key)) ||
      [usage.inputTokens, usage.outputTokens, usage.cachedInputTokens].some(value => !Number.isSafeInteger(value) || value < 0) ||
      usage.cachedInputTokens > usage.inputTokens) held('INVALID_RECEIPT');
  validateModelOutput(result.text, request);
  return result;
}


