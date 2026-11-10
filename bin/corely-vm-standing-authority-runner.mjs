#!/usr/bin/env node
// Explicit one-shot operator diagnostic. This is neither run-gateway nor an
// OpenAI/credits renewal daemon, and requires no provider or bridge files.
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { openCorelyVmModelIdentity } from './corely-vm-model-worker.mjs';
import { assertIsolatedSessionEnvironment } from './siwc-local-vm.mjs';
import { VmModelJobClientError, CORELY_VM_MODEL_JOB_ISSUER } from './corely-vm-model-job-client.mjs';

const DAY_MS = 86_400_000, MAX_RUN_MS = 30 * DAY_MS, STATUS_INTERVAL_MS = 60_000, MAX_RENEW_LEAD_MS = 15 * 60_000;
const held = () => new Error('CORELY_VM_STANDING_DIAGNOSTIC_HELD');
const flags = Object.freeze({ modelCalls: 0, providerRequestsMade: 0, apiFallbackUsed: false, paidCreditsUsed: false });
const renewalLead = seconds => Math.min(MAX_RENEW_LEAD_MS, seconds * 200);

export async function runCorelyVmStandingDiagnostic({ client, signal, onReceipt = () => {}, now = Date.now,
  monotonicNow = () => performance.now(), sleep = (ms, active) => delay(ms, undefined, { signal: active }), maximumRuntimeMs = MAX_RUN_MS } = {}) {
  if (!client || !['renew', 'childStatus', 'close'].every(key => typeof client[key] === 'function') || !(signal instanceof AbortSignal) ||
      ![onReceipt, now, monotonicNow, sleep].every(value => typeof value === 'function') ||
      !Number.isSafeInteger(maximumRuntimeMs) || maximumRuntimeMs < 1 || maximumRuntimeMs > MAX_RUN_MS) throw held();
  let wall = -1, mono = -1, current, parentDeadline, childDeadline;
  const clock = () => {
    const nextWall = now(), nextMono = monotonicNow();
    if (!Number.isSafeInteger(nextWall) || nextWall < 0 || nextWall < wall || nextWall > Number.MAX_SAFE_INTEGER - MAX_RUN_MS - 30_000 ||
        !Number.isFinite(nextMono) || nextMono < 0 || nextMono < mono || nextMono > Number.MAX_SAFE_INTEGER - MAX_RUN_MS) throw held();
    wall = nextWall; mono = nextMono;
  };
  const renew = async () => {
    const value = await client.renew(); clock();
    if (signal.aborted || value.status !== 'CORELY_VM_STANDING_RENEWAL_VERIFIED' || !Number.isSafeInteger(value.generation) || value.generation < 1 ||
        !Number.isSafeInteger(value.standingExpiresAt) || !Number.isSafeInteger(value.childExpiresAt) || value.childExpiresAt <= wall ||
        value.childExpiresAt > value.standingExpiresAt || value.standingExpiresAt > wall + MAX_RUN_MS + 30_000 ||
        !Number.isSafeInteger(value.maxChildSeconds) || value.maxChildSeconds < 1 || value.maxChildSeconds > DAY_MS / 1000 ||
        value.childExpiresAt > wall + value.maxChildSeconds * 1000 + 30_000 ||
        value.syntheticOnly !== true || value.apiFallbackEnabled !== false || value.noPaidCredits !== true ||
        value.predecessorDenialVerified !== Boolean(current) ||
        (value.childExpiresAt < value.standingExpiresAt && value.childExpiresAt - wall <= renewalLead(value.maxChildSeconds)) ||
        (current && (value.generation !== current.generation + 1 || value.standingExpiresAt !== current.standingExpiresAt ||
          value.maxChildSeconds !== current.maxChildSeconds || value.childExpiresAt <= current.childExpiresAt))) throw held();
    if (!current) parentDeadline = mono + value.standingExpiresAt - wall;
    childDeadline = Math.min(parentDeadline, mono + value.childExpiresAt - wall);
    current = value;
    await onReceipt(Object.freeze({ status: 'CORELY_VM_STANDING_DIAGNOSTIC_CHILD_VERIFIED', generation: value.generation,
      standingExpiresAt: value.standingExpiresAt, childExpiresAt: value.childExpiresAt, maxChildSeconds: value.maxChildSeconds,
      predecessorDenialVerified: value.predecessorDenialVerified, ...flags }));
  };
  const stopped = reason => Object.freeze({ status: 'CORELY_VM_STANDING_DIAGNOSTIC_STOPPED', reason, ...flags });
  try {
    if (signal.aborted) return stopped('OPERATOR_STOPPED');
    clock(); const runtimeDeadline = mono + maximumRuntimeMs;
    await renew();
    let checkChild = false;
    for (;;) {
      if (signal.aborted) return stopped('OPERATOR_STOPPED');
      clock();
      const parentRemaining = Math.min(current.standingExpiresAt - wall, parentDeadline - mono);
      if (parentRemaining <= 0) return stopped('STANDING_EXPIRED');
      if (mono >= runtimeDeadline) return stopped('RUN_LIMIT');
      const childRemaining = Math.min(current.childExpiresAt - wall, childDeadline - mono);
      if (childRemaining <= 0) throw held();
      const canExtendChild = current.childExpiresAt < current.standingExpiresAt;
      const lead = canExtendChild ? renewalLead(current.maxChildSeconds) : 0;
      if (canExtendChild && childRemaining <= lead) {
        await renew(); checkChild = false; continue;
      }
      if (checkChild) {
        const read = await client.childStatus();
        if (read.status === 'CORELY_VM_STANDING_CHILD_DENIED' && read.errorClass === 'invalid_token' &&
            read.freshProofUsed === true && read.originalChildUnexpired === true) {
          await onReceipt(Object.freeze({ status: 'CORELY_VM_STANDING_DIAGNOSTIC_CHILD_DENIED', generation: current.generation,
            childExpiresAt: current.childExpiresAt, httpStatus: 401, errorClass: 'invalid_token', ...flags }));
          return stopped('CHILD_DENIED');
        }
        if (read.status !== 'CORELY_VM_STANDING_CHILD_VALID' || read.expiresAt !== current.childExpiresAt ||
            read.syntheticOnly !== true || read.apiFallbackEnabled !== false) throw held();
      }
      const previousMono = mono, previousWall = wall;
      await sleep(Math.max(1, Math.ceil(Math.min(STATUS_INTERVAL_MS, parentRemaining, runtimeDeadline - mono,
        childRemaining - lead))), signal);
      if (signal.aborted) return stopped('OPERATOR_STOPPED');
      clock(); if (mono === previousMono && wall === previousWall) throw held();
      checkChild = true;
    }
  } catch (error) {
    // If renewal may have committed, preserve that hold even during shutdown.
    // Restart only after a normal clean stop, never automatically after HOLD.
    if (error instanceof VmModelJobClientError && error.code === 'STANDING_RENEWAL_RECOVERY_REQUIRED') throw error;
    if (signal.aborted) return stopped('OPERATOR_STOPPED');
    throw held();
  } finally { client.close(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  const outputFailed = () => { process.exitCode = 1; stop(); };
  process.stdout.on('error', outputFailed);
  const emit = value => process.stdout.write(`${JSON.stringify(value)}\n`);
  const fetchImpl = async (endpoint, init) => {
    const operation = ['prepare', 'status', 'renew', 'child-status']
      .find(name => endpoint === `${CORELY_VM_MODEL_JOB_ISSUER}/standing/${name}`);
    if (!operation || init.redirect !== 'error' || init.credentials !== 'omit' || init.cache !== 'no-store') throw held();
    const traceId = randomBytes(16).toString('hex'), startedAt = new Date().toISOString();
    try {
      const response = await fetch(endpoint, { ...init, headers: { ...init.headers, 'X-Cloud-Trace-Context': `${traceId}/0;o=1` } });
      emit({ status: 'CORELY_VM_STANDING_DIAGNOSTIC_HTTP', operation, traceId, startedAt, httpStatus: response.status });
      return response;
    } catch {
      emit({ status: 'CORELY_VM_STANDING_DIAGNOSTIC_HTTP_UNCERTAIN', operation, traceId, startedAt });
      throw held();
    }
  };
  let identity, client;
  try {
    const command = process.argv[2];
    if (process.argv.length !== 3 || !['prepare', 'run'].includes(command)) throw held();
    assertIsolatedSessionEnvironment();
    identity = await openCorelyVmModelIdentity('/state', { standingOnly: true });
    client = await identity.connectStanding({ signal: controller.signal, fetchImpl });
    if (command === 'prepare') {
      const request = await client.prepare();
      // Ephemeral authenticated Ops handoff only; no token, proof or key.
      emit({ status: request.status, verificationUriComplete: request.verification_uri_complete,
        requestExpiresAt: request.requestExpiresAt, standingExpiresAt: request.standingExpiresAt, ...flags });
    } else {
      const receipt = await runCorelyVmStandingDiagnostic({ client, signal: controller.signal, onReceipt: emit });
      emit(receipt);
      if (receipt.reason === 'CHILD_DENIED') process.exitCode = 1;
    }
  } catch (error) {
    emit({ status: 'CORELY_VM_STANDING_DIAGNOSTIC_HELD', recoveryRequired: error instanceof VmModelJobClientError &&
      error.code === 'STANDING_RENEWAL_RECOVERY_REQUIRED', ...flags });
    process.exitCode = 1;
  } finally {
    client?.close();
    try { await identity?.close(); }
    catch { emit({ status: 'CORELY_VM_STANDING_DIAGNOSTIC_CLEANUP_UNCONFIRMED', ...flags }); process.exitCode = 1; }
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
  }
}
