import { chromium } from '@playwright/test';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { parseStrictJson } from './strict-json.mjs';

// Polling is observer-local and does not drive Host state; changing it affects capture latency
// and browser load, while the two-minute default bounds one manual physical transition interval.
const OBSERVER_POLL_INTERVAL_MS = 25;
const DEFAULT_OBSERVER_TIMEOUT_MS = 120_000;
const MAX_OBSERVER_TIMEOUT_MS = 120_000;
// These evidence-v1 transcript budgets are observer-local safety limits, not Host cardinality
// limits. Counts are deliberately far above the bounded formal sequence while bytes remain below
// the package ceiling. Raising them increases retained network data and allocation; lowering them
// can reject a valid browser run before sealing.
const MAX_WEBSOCKET_EVENTS = 4096;
const MAX_WEBSOCKET_FRAME_BYTES = 64 * 1024;
const MAX_WEBSOCKET_TOTAL_BYTES = 8 * 1024 * 1024;
const MAX_HTTP_RESPONSES = 4096;
// Sixteen covers Chrome's normal parallel document/asset/API activity for the required page while
// bounding retained Playwright Response objects. Raising it increases outstanding browser-backed
// objects and memory; lowering it can reject ordinary parallel loading.
const MAX_PENDING_HTTP_RESPONSES = 16;
const MAX_HTTP_RESPONSE_BYTES = 1024 * 1024;
const MAX_HTTP_TOTAL_BYTES = 16 * 1024 * 1024;
// Artifact/package ceilings mirror verifier v1. Increasing them expands write and verifier-read
// exposure; decreasing them makes previously conforming evidence packages incompatible.
const MAX_OBSERVER_ARTIFACT_BYTES = 16 * 1024 * 1024;
const MAX_OBSERVER_PACKAGE_BYTES = 32 * 1024 * 1024;
// A 64 MiB decoded-pixel budget admits the contract's bounded viewport captures. Raising it
// increases image decode allocation; lowering it can reject valid high-density Chrome screenshots.
const MAX_SCREENSHOT_DECODED_BYTES = 64 * 1024 * 1024;
// Visible DOM text is retained only to bind the screenshot state to the same page. These v1 limits
// bound JSON size and privacy scanning; changing either value requires the independent verifier's
// contract constants to change in lockstep and affects existing package compatibility.
const MAX_VISIBLE_TEXT_ITEMS = 512;
const MAX_VISIBLE_TEXT_BYTES = 4096;
const execFileAsync = promisify(execFile);
// These values are the Identifier and TeamIdentifier reported by macOS codesign for the official
// Google Chrome bundle. Changing either admits a different signed application identity and requires
// a new acceptance review plus verifier-compatible evidence contract.
const GOOGLE_CHROME_APPLICATION_ID = 'com.google.Chrome';
const GOOGLE_CHROME_TEAM_ID = 'EQHXZ8M8AV';
// The production Host serves exactly this document, stylesheet, and script for Sensing. Changing
// the set changes the asset digest preimage and requires coordinated Host routes and package checks.
const SERVED_ASSET_PATHS = ['/', '/assets/app.css', '/assets/app.js'];
// This is the closed Knowledge vocabulary from api-ui-v1's relationship schema. Adding a valid
// state requires updating this map or the observer will fail closed; removing one makes runs that
// encounter that state ineligible for evidence capture.
const RELATIONSHIP_KNOWLEDGE_DOM = new Map([
  ['known:changing', 'Changing'],
  ['known:stable', 'Stable'],
  ['unknown:ambiguous_evidence', 'Unknown(AmbiguousEvidence)'],
  ['unknown:baseline_learning', 'Unknown(BaselineLearning)'],
  ['unknown:baseline_missing', 'Unknown(BaselineMissing)'],
  ['unknown:frozen', 'Unknown(Frozen)'],
  ['unknown:inactive', 'Unknown(Inactive)'],
  ['unknown:insufficient_coverage', 'Unknown(InsufficientCoverage)'],
  ['unknown:low_quality', 'Unknown(LowQuality)'],
  ['unknown:missing_data', 'Unknown(MissingData)'],
  ['unknown:non_finite', 'Unknown(NonFinite)'],
  ['unknown:profile_mismatch', 'Unknown(ProfileMismatch)'],
  ['unknown:stale', 'Unknown(Stale)'],
  ['unknown:time_uncertain', 'Unknown(TimeUncertain)'],
]);

export class ObserverRetentionBudget {
  constructor() {
    this.websocketEvents = 0;
    this.websocketBytes = 0;
    this.httpResponses = 0;
    this.httpBytes = 0;
    this.pendingHttpResponses = 0;
  }

  recordWebSocketEvent(frameBytes = 0) {
    if (!Number.isSafeInteger(frameBytes) || frameBytes < 0
      || frameBytes > MAX_WEBSOCKET_FRAME_BYTES) {
      throw new Error('WebSocket frame exceeds the observer retention bound');
    }
    this.websocketEvents += 1;
    this.websocketBytes += frameBytes;
    if (this.websocketEvents > MAX_WEBSOCKET_EVENTS
      || this.websocketBytes > MAX_WEBSOCKET_TOTAL_BYTES) {
      throw new Error('WebSocket transcript exceeds the observer retention bound');
    }
  }

  reserveHttpResponse() {
    const httpResponses = this.httpResponses + 1;
    const pendingHttpResponses = this.pendingHttpResponses + 1;
    if (httpResponses > MAX_HTTP_RESPONSES) {
      throw new Error('relationship HTTP response count exceeds the observer retention bound');
    }
    if (pendingHttpResponses > MAX_PENDING_HTTP_RESPONSES) {
      throw new Error('pending HTTP response count exceeds the observer retention bound');
    }
    this.httpResponses = httpResponses;
    this.pendingHttpResponses = pendingHttpResponses;
  }

  beginHttpResponse(contentLength) {
    if (typeof contentLength !== 'string' || !/^(0|[1-9][0-9]*)$/.test(contentLength)) {
      throw new Error('relationship HTTP response requires a bounded Content-Length');
    }
    const bytes = Number(contentLength);
    if (!Number.isSafeInteger(bytes) || bytes > MAX_HTTP_RESPONSE_BYTES) {
      throw new Error('relationship HTTP response exceeds the observer retention bound');
    }
    const httpBytes = this.httpBytes + bytes;
    if (httpBytes > MAX_HTTP_TOTAL_BYTES) {
      throw new Error('relationship HTTP responses exceed the observer retention bound');
    }
    this.httpBytes = httpBytes;
    return bytes;
  }

  finishHttpResponse(expectedBytes, actualBytes) {
    if (actualBytes !== expectedBytes) {
      throw new Error('relationship HTTP response disagrees with Content-Length');
    }
  }

  releaseHttpResponse() {
    if (this.pendingHttpResponses === 0) {
      throw new Error('HTTP response reservation is incompatible');
    }
    this.pendingHttpResponses -= 1;
  }

  validateArtifacts(artifacts) {
    let total = 0;
    for (const [path, , bytes] of artifacts) {
      if (bytes.length > MAX_OBSERVER_ARTIFACT_BYTES) {
        throw new Error(`observer artifact exceeds the bounded member size: ${path}`);
      }
      total += bytes.length;
      if (total > MAX_OBSERVER_PACKAGE_BYTES) {
        throw new Error('observer artifacts exceed the bounded package size');
      }
    }
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function servedAssetSha256(responses) {
  if (!(responses instanceof Map)
    || responses.size !== SERVED_ASSET_PATHS.length
    || SERVED_ASSET_PATHS.some((path) => !Buffer.isBuffer(responses.get(path)))) {
    throw new Error('served asset response set is incomplete');
  }
  const digest = createHash('sha256');
  for (const path of SERVED_ASSET_PATHS) {
    const bytes = responses.get(path);
    const pathLength = Buffer.alloc(8);
    pathLength.writeBigUInt64BE(BigInt(Buffer.byteLength(path)));
    const byteLength = Buffer.alloc(8);
    byteLength.writeBigUInt64BE(BigInt(bytes.length));
    digest.update(pathLength).update(path).update(byteLength).update(bytes);
  }
  return digest.digest('hex');
}

function exactKeys(value, required, optional = []) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || required.some((key) => !Object.hasOwn(value, key))) return false;
  const allowed = new Set([...required, ...optional]);
  return Object.keys(value).every((key) => allowed.has(key));
}

function traceSnapshot(snapshot) {
  return snapshot;
}

export function screenshotState(snapshot) {
  return snapshot;
}

function parseLiveMessage(text) {
  const value = JSON.parse(text);
  if (!exactKeys(value, ['http_schema_version', 'delivery_sequence', 'projection_commit', 'payload'])
    || value.http_schema_version !== 1
    || typeof value.delivery_sequence !== 'string'
    || !exactKeys(value.projection_commit, ['sequence', 'store_id'])
    || typeof value.projection_commit.sequence !== 'string'
    || typeof value.projection_commit.store_id !== 'string'
    || !exactKeys(value.payload, ['kind'])
    || value.payload.kind !== 'projection_watermark') {
    throw new Error('WebSocket payload is not the closed watermark envelope');
  }
  return value;
}

function canonicalU64(value) {
  return typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)
    && BigInt(value) <= 18_446_744_073_709_551_615n;
}

function canonicalId(value) {
  if (typeof value !== 'string' || !/[^\p{White_Space}]/u.test(value)
    || Buffer.byteLength(value) > 0xffff_ffff) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

function projectionWatermark(value, committed = false) {
  return exactKeys(value, ['store_id', 'sequence'])
    && typeof value.store_id === 'string' && /^[0-9a-f]{64}$/.test(value.store_id)
    && canonicalU64(value.sequence) && (!committed || value.sequence !== '0');
}

function viewReceipt(value) {
  return exactKeys(value, [
    'projection_commit', 'session_id', 'first_record_seq', 'last_record_seq',
    'decoder_version', 'conditioning_version', 'algorithm_version',
  ])
    && projectionWatermark(value.projection_commit, true)
    && canonicalId(value.session_id)
    && canonicalU64(value.first_record_seq)
    && canonicalU64(value.last_record_seq)
    && BigInt(value.first_record_seq) <= BigInt(value.last_record_seq)
    && canonicalId(value.decoder_version)
    && canonicalId(value.conditioning_version)
    && canonicalId(value.algorithm_version);
}

function relationshipKnowledgeKey(value) {
  if (exactKeys(value, ['kind', 'value']) && value.kind === 'known') {
    const key = `known:${value.value}`;
    return RELATIONSHIP_KNOWLEDGE_DOM.has(key) ? key : null;
  }
  if (exactKeys(value, ['kind', 'reason']) && value.kind === 'unknown') {
    const key = `unknown:${value.reason}`;
    return RELATIONSHIP_KNOWLEDGE_DOM.has(key) ? key : null;
  }
  return null;
}

function relationshipChange(value) {
  return exactKeys(value, ['previous', 'current', 'changed_at'])
    && relationshipKnowledgeKey(value.previous) !== null
    && relationshipKnowledgeKey(value.current) !== null
    && canonicalU64(value.changed_at);
}

function relationshipKind(value) {
  if (!exactKeys(value, ['http_schema_version', 'kind', 'resource', 'receipt'], ['data'])
    || value.http_schema_version !== 1 || value.resource !== 'relationship_latest'
    || !viewReceipt(value.receipt)) {
    throw new Error('relationship HTTP body is outside the closed schema');
  }
  if (value.kind === 'empty' && !Object.hasOwn(value, 'data')) return 'other';
  if (value.kind !== 'ok' || !exactKeys(value.data, [
    'session_id', 'link', 'profile', 'knowledge', 'result_time', 'creator_commit',
  ], ['most_recent_change'])) {
    throw new Error('relationship HTTP body is outside the closed schema');
  }
  const data = value.data;
  const knowledge = relationshipKnowledgeKey(data.knowledge);
  if (!canonicalId(data.session_id) || !canonicalId(data.link)
    || typeof data.profile !== 'string' || !/^[0-9a-f]{64}$/.test(data.profile)
    || knowledge === null || !canonicalU64(data.result_time)
    || !projectionWatermark(data.creator_commit, true)
    || data.creator_commit.store_id !== value.receipt.projection_commit.store_id
    || BigInt(data.creator_commit.sequence) > BigInt(value.receipt.projection_commit.sequence)
    || value.receipt.session_id !== data.session_id
    || (Object.hasOwn(data, 'most_recent_change')
      && !relationshipChange(data.most_recent_change))) {
    throw new Error('relationship HTTP body is outside the closed schema');
  }
  if (knowledge === 'unknown:baseline_learning') return 'unknown';
  if (knowledge === 'known:stable') return 'stable';
  return 'other';
}

function parseRelationshipBody(body) {
  const text = body.toString('utf8');
  if (!Buffer.from(text).equals(body)) {
    throw new Error('relationship HTTP body is not exact UTF-8');
  }
  return parseStrictJson(text);
}

function domKnowledge(text) {
  for (const [knowledge, label] of RELATIONSHIP_KNOWLEDGE_DOM) {
    if (text === label) {
      if (knowledge === 'unknown:baseline_learning') return knowledge;
      if (knowledge === 'known:stable') return 'stable';
      return 'other';
    }
  }
  throw new Error(`unexpected DOM relationship state: ${text}`);
}

function stripNanoseconds(text) {
  const match = /^(0|[1-9][0-9]*) ns$/.exec(text);
  if (!match) throw new Error(`unexpected DOM nanosecond value: ${text}`);
  return match[1];
}

function validateViewport(width, height, scale) {
  const pixelWidth = width * scale;
  const pixelHeight = height * scale;
  if (!Number.isSafeInteger(pixelWidth) || pixelWidth <= 0
    || !Number.isSafeInteger(pixelHeight) || pixelHeight <= 0
    || pixelWidth * pixelHeight * 4 > MAX_SCREENSHOT_DECODED_BYTES) {
    throw new Error('Chrome viewport exceeds the observer screenshot bound');
  }
}

async function documentIdentity(cdp) {
  const { frameTree } = await cdp.send('Page.getFrameTree');
  const { id, loaderId } = frameTree.frame;
  if (typeof id !== 'string' || id === '' || typeof loaderId !== 'string' || loaderId === '') {
    throw new Error('Chrome main document identity is unavailable');
  }
  return sha256(Buffer.from(`${id}\0${loaderId}`));
}

async function readRelationshipDom(page, cdp, expectedDocumentId = null) {
  const documentBefore = await documentIdentity(cdp);
  const value = await page.evaluate(() => {
    const visible = (element) => {
      const style = window.getComputedStyle(element);
      return style.display !== 'none'
        && style.visibility !== 'hidden'
        && style.opacity !== '0'
        && element.getClientRects().length > 0;
    };
    const opaqueTags = new Set(['CANVAS', 'EMBED', 'IFRAME', 'IMG', 'OBJECT', 'PICTURE', 'SVG', 'VIDEO']);
    const opaqueVisualSurfaces = [...document.querySelectorAll('*')]
      .filter((element) => visible(element) && (
        opaqueTags.has(element.tagName)
          || window.getComputedStyle(element).backgroundImage !== 'none'
      ))
      .map((element) => element.tagName.toLowerCase());
    const change = document.querySelector('#relationship-change');
    const relationshipState = document.querySelector('[data-testid="relationship-state"]');
    const stateBounds = relationshipState.getBoundingClientRect();
    return {
      change_state: change.hidden
        ? null : document.querySelector('#relationship-change-state').textContent,
      change_time: change.hidden
        ? null : document.querySelector('#relationship-change-time').textContent,
      connection_detail: document.querySelector('#connection-detail').textContent,
      connection_text: document.querySelector('[data-testid="connection-state"]').textContent,
      knowledge: document.querySelector('[data-testid="relationship-state"]').textContent,
      state_bounds: {
        height: stateBounds.height,
        width: stateBounds.width,
        x: stateBounds.x,
        y: stateBounds.y,
      },
      opaque_visual_surfaces: opaqueVisualSurfaces,
      result_time: document.querySelector('[data-testid="relationship-result-time"]').textContent,
      selection: {
        link: document.querySelector('#relationship-link-select').value,
        profile: document.querySelector('#relationship-profile-select').value,
        session_id: document.querySelector('#relationship-session-select').value,
      },
      stale: !document.querySelector('#stale-indicator').hidden,
      visible_text: document.body.innerText.split('\n').map((text) => text.trim()).filter(Boolean),
      viewport: {
        height: window.innerHeight,
        scale: window.devicePixelRatio,
        width: window.innerWidth,
      },
    };
  });
  const documentAfter = await documentIdentity(cdp);
  if (documentBefore !== documentAfter
    || (expectedDocumentId !== null && documentAfter !== expectedDocumentId)) {
    throw new Error('Sensing page document changed during evidence capture');
  }
  if (!Object.values(value.state_bounds).every(Number.isInteger)
    || value.state_bounds.width <= 0 || value.state_bounds.height <= 0) {
    throw new Error('relationship state bounds are not positive integral CSS pixels');
  }
  validateViewport(value.viewport.width, value.viewport.height, value.viewport.scale);
  if (value.visible_text.length > MAX_VISIBLE_TEXT_ITEMS
    || value.visible_text.some((text) => typeof text !== 'string'
      || text.length > MAX_VISIBLE_TEXT_BYTES)
    || value.opaque_visual_surfaces.length !== 0) {
    throw new Error('Sensing page has an unbounded or opaque visible surface');
  }
  return {
    change_state: value.change_state,
    change_time: value.change_time === null ? null : stripNanoseconds(value.change_time),
    connection_detail: value.connection_detail,
    connection_text: value.connection_text,
    document_id: documentAfter,
    knowledge: domKnowledge(value.knowledge),
    state_bounds: value.state_bounds,
    opaque_visual_surfaces: value.opaque_visual_surfaces,
    result_time: stripNanoseconds(value.result_time),
    selection: value.selection,
    stale: value.stale,
    visible_text: value.visible_text,
  };
}

function matchRelationshipDom(value, dom) {
  const expectedState = relationshipKind(value) === 'unknown'
    ? 'unknown:baseline_learning' : 'stable';
  const expectedSelection = {
    link: value.data.link,
    profile: value.data.profile,
    session_id: value.data.session_id,
  };
  if (canonicalJson(dom.selection) !== canonicalJson(expectedSelection)) {
    throw new Error('relationship DOM selection disagrees with the HTTP target');
  }
  if (dom.knowledge !== expectedState) {
    if (dom.knowledge === 'unknown:baseline_learning' || dom.knowledge === 'stable') {
      throw new Error('relationship DOM target disagrees with the HTTP target');
    }
    return null;
  }
  if (dom.result_time !== value.data.result_time) {
    if (BigInt(dom.result_time) > BigInt(value.data.result_time)) return null;
    throw new Error('relationship DOM result time disagrees with the HTTP target');
  }
  return dom;
}

async function matchingRelationshipDom(page, cdp, value, expectedDocumentId) {
  const dom = await readRelationshipDom(page, cdp, expectedDocumentId);
  return matchRelationshipDom(value, dom);
}

async function captureRelationshipPage(page, cdp, value, expectedDocumentId, clock, deadlineMs) {
  remainingObserverMs(clock, deadlineMs, 'relationship DOM');
  const before = await matchingRelationshipDom(page, cdp, value, expectedDocumentId);
  if (before === null) return null;
  await page.waitForFunction(() => (
    document.querySelector('[data-testid="connection-state"]')?.textContent === 'LIVE'
  ), null, { timeout: remainingObserverMs(clock, deadlineMs, 'LIVE Sensing page') });
  if (before.connection_text !== 'LIVE'
    || before.stale) {
    return null;
  }
  const screenshot = await page.screenshot({
    animations: 'disabled',
    fullPage: false,
    type: 'png',
  });
  const after = await readRelationshipDom(page, cdp, before.document_id);
  if (canonicalJson(screenshotState(before)) !== canonicalJson(screenshotState(after))) {
    return null;
  }
  const { state_bounds: stateBounds, ...dom } = before;
  return { dom, screenshot, stateBounds };
}

async function sha256File(path) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest('hex');
}

export async function signedChromeApplication(
  endpoint,
  run = execFileAsync,
  hashExecutable = sha256File,
) {
  if (process.platform !== 'darwin') {
    throw new Error('official Google Chrome identity requires macOS code signing');
  }
  const url = new URL(endpoint);
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) || url.port === '') {
    throw new Error('Chrome CDP endpoint must be a local explicit port');
  }
  const { stdout: listeners } = await run('lsof', [
    '-nP', '-a', `-iTCP:${url.port}`, '-sTCP:LISTEN', '-Fp',
  ]);
  const pids = [...new Set(
    [...listeners.matchAll(/^p([0-9]+)$/gm)].map((match) => match[1]),
  )];
  if (pids.length !== 1) throw new Error('Chrome CDP listener identity is ambiguous');
  const { stdout: command } = await run('ps', ['-p', pids[0], '-o', 'comm=']);
  const executable = command.trim();
  if (!executable.endsWith('/Google Chrome.app/Contents/MacOS/Google Chrome')) {
    throw new Error('Chrome CDP listener is not the Google Chrome application');
  }
  await run('codesign', ['--verify', '--verbose=4', executable]);
  const signature = await run('codesign', ['-dv', '--verbose=4', executable]);
  const description = `${signature.stdout}\n${signature.stderr}`;
  const applicationId = /^Identifier=(.+)$/m.exec(description)?.[1];
  const teamId = /^TeamIdentifier=(.+)$/m.exec(description)?.[1];
  return {
    application_id: applicationId,
    executable_sha256: await hashExecutable(executable),
    signature_verified: true,
    team_id: teamId,
  };
}

export async function chromeIdentity(
  browserEndpoint,
  fetchImpl = fetch,
  applicationIdentity = signedChromeApplication,
) {
  if (!browserEndpoint.startsWith('cdp:http://')
    && !browserEndpoint.startsWith('cdp:https://')) {
    throw new Error('observer requires a Chrome CDP HTTP endpoint');
  }
  const endpoint = browserEndpoint.slice('cdp:'.length).replace(/\/$/, '');
  const response = await fetchImpl(`${endpoint}/json/version`);
  if (!response.ok) throw new Error('Chrome CDP version endpoint is unavailable');
  const match = /^Chrome\/(.+)$/.exec((await response.json()).Browser);
  if (!match) throw new Error('CDP endpoint is not Google Chrome');
  const identity = await applicationIdentity(endpoint);
  if (identity.application_id !== GOOGLE_CHROME_APPLICATION_ID
    || identity.team_id !== GOOGLE_CHROME_TEAM_ID
    || identity.signature_verified !== true
    || !/^[0-9a-f]{64}$/.test(identity.executable_sha256)) {
    throw new Error('CDP endpoint is not the signed Google Chrome application');
  }
  return {
    application_id: identity.application_id,
    endpoint,
    executable_sha256: identity.executable_sha256,
    name: 'Chrome',
    team_id: identity.team_id,
    version: match[1],
  };
}

function remainingObserverMs(clock, deadlineMs, label) {
  const remaining = Math.ceil(deadlineMs - clock.monotonicNowMs());
  if (remaining <= 0) throw new Error(`${label} was not observed before the observer deadline`);
  return remaining;
}

async function waitFor(clock, deadlineMs, read, accept, label) {
  let last;
  while (clock.monotonicNowMs() < deadlineMs) {
    last = await read();
    if (accept(last)) return last;
    await clock.sleep(OBSERVER_POLL_INTERVAL_MS);
  }
  throw new Error(`${label} was not observed: ${JSON.stringify(last)}`);
}

async function writeNew(path, bytes) {
  await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
}

function systemObserverClock() {
  return {
    monotonicNowMs: () => performance.now(),
    sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
    utcNowNs: () => BigInt(Date.now()) * 1_000_000n,
  };
}

export function observerTiming(clock, timeoutMs) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error('observer timeout is invalid');
  }
  if (timeoutMs > MAX_OBSERVER_TIMEOUT_MS) {
    throw new Error('observer timeout exceeds its bounded maximum');
  }
  const deadlineMs = clock.monotonicNowMs() + timeoutMs;
  const startedUtcNs = clock.utcNowNs();
  return { deadlineMs, startedUtcNs };
}

function isLoopbackHostname(hostname) {
  if (hostname === 'localhost' || hostname === '[::1]') return true;
  const octets = hostname.split('.').map(Number);
  return octets.length === 4
    && octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
    && octets[0] === 127;
}

export function productionLiveWebSocketUrl(baseUrl) {
  const url = new URL(baseUrl);
  if (url.protocol !== 'http:') {
    throw new Error('production observer requires an HTTP Host URL');
  }
  if (!isLoopbackHostname(url.hostname)) {
    throw new Error('production observer requires a loopback Host URL');
  }
  if (!url.port) {
    throw new Error('production observer requires an explicit Host port');
  }
  url.protocol = 'ws:';
  url.pathname = '/api/live';
  url.search = '';
  url.hash = '';
  return url.toString();
}

function retainedLiveWebSocketUrl(urlText) {
  const url = new URL(urlText);
  return `ws://loopback:${url.port}/api/live`;
}

export async function observe(clock, args = process.argv.slice(2)) {
const [root, browserEndpoint, baseUrl, pageInstanceId,
  timeoutText = String(DEFAULT_OBSERVER_TIMEOUT_MS)] = args;
if (!root || !browserEndpoint || !baseUrl || !pageInstanceId) {
  throw new Error('usage: node scripts/evidence-observer.mjs ROOT BROWSER_ENDPOINT BASE_URL PAGE_INSTANCE_ID [TIMEOUT_MS]');
}
const timeoutMs = Number(timeoutText);
const { deadlineMs, startedUtcNs } = observerTiming(clock, timeoutMs);
let observerTimer;
const timeoutFailure = new Promise((_, reject) => {
  observerTimer = setTimeout(
    () => reject(new Error('evidence observer exceeded its total deadline')),
    timeoutMs,
  );
});
const operation = (async () => {
const wait = (read, accept, label) => waitFor(clock, deadlineMs, read, accept, label);
const expectedPageUrl = new URL(baseUrl);
const liveWebSocketUrl = productionLiveWebSocketUrl(baseUrl);
const retainedWebSocketUrl = retainedLiveWebSocketUrl(liveWebSocketUrl);
const browserIdentity = await chromeIdentity(browserEndpoint);
const browser = await chromium.connectOverCDP(browserIdentity.endpoint);
const pages = browser.contexts().flatMap((context) => context.pages());
if (pages.length !== 1) {
  throw new Error(`observer requires exactly one already-open Chrome page; found ${pages.length}`);
}
const [page] = pages;
const cdp = await page.context().newCDPSession(page);
const budget = new ObserverRetentionBudget();
const servedAssetResponses = new Map();
const websocketEvents = [];
let socketCount = 0;
let activeSocketId = null;
let disconnected = false;
let reconnected = false;
let finished = false;
let responseChain = Promise.resolve();
let retainedDocumentId = null;
let retainedSelection = null;
let unknownBody = null;
let unknownDom = null;
let unknownStateBounds = null;
let unknownScreenshot = null;
let stablePreBody = null;
let stablePreValue = null;
let stablePreDom = null;
let stablePreStateBounds = null;
let stablePreScreenshot = null;
let stablePreTrigger = null;
let stablePostBody = null;
let stablePostValue = null;
let stablePostDom = null;
let stablePostStateBounds = null;
let stablePostScreenshot = null;
let stablePostTrigger = null;

function pushSocketEvent(event) {
  budget.recordWebSocketEvent(event.observed_bytes ?? 0);
  const { observed_bytes: _, ...retained } = event;
  const ordered = { ...retained, order: String(websocketEvents.length) };
  websocketEvents.push(ordered);
  return ordered;
}

page.on('websocket', (socket) => {
  if (socket.url() !== liveWebSocketUrl || activeSocketId !== null || socketCount >= 2) {
    throw new Error('Chrome opened an incompatible production WebSocket');
  }
  const socketId = String(socketCount);
  socketCount += 1;
  activeSocketId = socketId;
  if (socketCount === 1) {
    pushSocketEvent({ kind: 'connected', socket_id: socketId, url: retainedWebSocketUrl });
  }
  else {
    if (!disconnected || reconnected) {
      throw new Error('Chrome WebSocket reconnection order is incompatible');
    }
    reconnected = true;
    pushSocketEvent({ kind: 'reconnected', socket_id: socketId, url: retainedWebSocketUrl });
  }
  socket.on('framereceived', ({ payload }) => {
    if (activeSocketId !== socketId) {
      throw new Error('Chrome WebSocket message arrived on an inactive socket');
    }
    if (typeof payload !== 'string') throw new Error('binary WebSocket frame is not allowed');
    const observedBytes = Buffer.byteLength(payload);
    const parsed = parseLiveMessage(payload);
    pushSocketEvent({
      delivery_sequence: parsed.delivery_sequence,
      kind: 'message',
      raw_text_sha256: sha256(Buffer.from(payload)),
      observed_bytes: observedBytes,
      socket_id: socketId,
      store_id: parsed.projection_commit.store_id,
      watermark: parsed.projection_commit.sequence,
    });
  });
  socket.on('close', () => {
    if (finished) return;
    if (activeSocketId !== socketId || disconnected) {
      throw new Error('Chrome WebSocket closed outside the controlled restart');
    }
    activeSocketId = null;
    disconnected = true;
    pushSocketEvent({ kind: 'disconnected', socket_id: socketId });
  });
});

function queueObservedHttp(response, consume) {
  budget.reserveHttpResponse();
  const observedBody = (async () => {
    try {
      remainingObserverMs(clock, deadlineMs, 'HTTP response');
      const expectedBytes = budget.beginHttpResponse(await response.headerValue('content-length'));
      const body = await response.body();
      budget.finishHttpResponse(expectedBytes, body.length);
      return body;
    } finally {
      budget.releaseHttpResponse();
    }
  })();
  responseChain = Promise.all([responseChain, observedBody])
    .then(([, body]) => consume(body));
}

page.on('response', (response) => {
  const url = new URL(response.url());
  if (response.request().method() !== 'GET' || url.origin !== expectedPageUrl.origin) return;
  if (SERVED_ASSET_PATHS.includes(url.pathname) && !url.search) {
    queueObservedHttp(response, (body) => {
      if (servedAssetResponses.has(url.pathname)) {
        throw new Error('served asset response was observed more than once');
      }
      servedAssetResponses.set(url.pathname, body);
    });
    return;
  }
  if (url.pathname !== '/api/relationships/latest' || !url.search) return;
  const beforeDisconnect = !disconnected;
  const afterReconnect = reconnected;
  const websocketEventLimit = websocketEvents.length;
  queueObservedHttp(response, async (body) => {
    const value = parseRelationshipBody(body);
    const kind = relationshipKind(value);
    if (value.kind === 'ok') {
      const responseSelection = {
        link: value.data.link,
        profile: value.data.profile,
        session_id: value.data.session_id,
      };
      if (retainedSelection === null) retainedSelection = responseSelection;
      else if (canonicalJson(retainedSelection) !== canonicalJson(responseSelection)) {
        throw new Error('relationship HTTP selection changed during observation');
      }
    }
    const websocketTrigger = websocketEvents
      .slice(0, websocketEventLimit)
      .findLast((event) => event.kind === 'message') ?? null;
    if (kind === 'unknown' && unknownBody === null) {
      const captured = await captureRelationshipPage(
        page, cdp, value, retainedDocumentId, clock, deadlineMs,
      );
      if (captured === null) {
        process.stdout.write(`${canonicalJson({
          page_instance_id: pageInstanceId,
          state: 'non-target-observed',
        })}\n`);
        return;
      }
      retainedDocumentId = captured.dom.document_id;
      unknownBody = body;
      ({ dom: unknownDom, screenshot: unknownScreenshot, stateBounds: unknownStateBounds } =
        captured);
      process.stdout.write(`${canonicalJson({
        page_instance_id: pageInstanceId,
        result_time: value.data.result_time,
        state: 'unknown-captured',
      })}\n`);
    } else if (kind === 'stable' && beforeDisconnect
      && value.data.result_time !== stablePreValue?.data.result_time) {
      if (websocketTrigger?.watermark !== value.data.creator_commit.sequence) return;
      const captured = await captureRelationshipPage(
        page, cdp, value, retainedDocumentId, clock, deadlineMs,
      );
      if (captured === null) return;
      stablePreBody = body;
      stablePreValue = value;
      stablePreTrigger = websocketTrigger;
      ({ dom: stablePreDom, screenshot: stablePreScreenshot,
        stateBounds: stablePreStateBounds } = captured);
      process.stdout.write(`${canonicalJson({
        page_instance_id: pageInstanceId,
        result_time: value.data.result_time,
        state: 'stable-pre-captured',
      })}\n`);
    } else if (kind === 'stable' && afterReconnect && stablePreValue
      && BigInt(value.data.result_time) > BigInt(stablePreValue.data.result_time)) {
      if (websocketTrigger?.watermark !== value.data.creator_commit.sequence) return;
      const captured = await captureRelationshipPage(
        page, cdp, value, retainedDocumentId, clock, deadlineMs,
      );
      if (captured === null) return;
      stablePostBody = body;
      stablePostValue = value;
      stablePostTrigger = websocketTrigger;
      ({ dom: stablePostDom, screenshot: stablePostScreenshot,
        stateBounds: stablePostStateBounds } = captured);
    }
  });
});

try {
  process.stdout.write(`${canonicalJson({ page_instance_id: pageInstanceId, state: 'ready' })}\n`);
  await wait(
    () => page.getByTestId('relationship-state').textContent(),
    (text) => text === 'Unknown(BaselineLearning)' && unknownDom !== null,
    'Unknown(BaselineLearning)',
  );
  const observedPageUrl = new URL(page.url());
  if (observedPageUrl.origin !== expectedPageUrl.origin
    || observedPageUrl.pathname !== expectedPageUrl.pathname) {
    throw new Error('attached Chrome page does not match the production Host URL');
  }
  const selection = unknownDom.selection;
  await wait(
    () => page.getByTestId('relationship-state').textContent(),
    (text) => text === 'Stable' && stablePreBody !== null,
    'pre-restart Stable',
  );
  await wait(
    async () => ({
      connection: await page.getByTestId('connection-state').textContent(),
      stale: await page.locator('#stale-indicator').isVisible(),
    }),
    (state) => disconnected && state.connection === 'POLLING' && state.stale,
    'stale retained result',
  );
  await responseChain;
  if (stablePreValue === null) throw new Error('pre-restart Stable HTTP observation is absent');
  const staleSnapshot = await readRelationshipDom(page, cdp, retainedDocumentId);
  if (canonicalJson(staleSnapshot.selection) !== canonicalJson(selection)) {
    throw new Error('Sensing selection changed before the Host restart');
  }
  await wait(
    () => page.locator('#connection-detail').textContent(),
    (text) => reconnected && text === 'Watermark received · reading complete HTTP resources',
    'resynchronizing HTTP read',
  );
  const resynchronizingSnapshot = await readRelationshipDom(page, cdp, retainedDocumentId);
  if (canonicalJson(resynchronizingSnapshot.selection) !== canonicalJson(selection)) {
    throw new Error('Sensing selection changed during Host resynchronization');
  }
  await wait(
    async () => ({
      connection: await page.getByTestId('connection-state').textContent(),
      state: await page.getByTestId('relationship-state').textContent(),
    }),
    (state) => state.connection === 'LIVE' && state.state === 'Stable' && stablePostBody !== null,
    'post-restart Stable',
  );
  await responseChain;
  if (stablePostValue === null) throw new Error('post-restart Stable HTTP observation is absent');

  const httpRoot = join(root, 'http');
  const screenshotRoot = join(root, 'screenshots');
  await mkdir(httpRoot, { mode: 0o700 });
  await mkdir(screenshotRoot, { mode: 0o700 });
  const artifacts = [
    ['chrome-trace.json', 'application/json', Buffer.from(canonicalJson({
      events: [
        { ...unknownDom, connection_state: 'LIVE', kind: 'unknown', state_bounds: unknownStateBounds,
          order: '0', screenshot: 'screenshots/unknown.png', screenshot_sha256: sha256(unknownScreenshot) },
        { ...stablePreDom, connection_state: 'LIVE', kind: 'stable_pre_restart',
          state_bounds: stablePreStateBounds, order: '1', screenshot: 'screenshots/stable-pre-restart.png',
          screenshot_sha256: sha256(stablePreScreenshot),
          trigger_websocket_order: stablePreTrigger.order,
          trigger_websocket_socket_id: stablePreTrigger.socket_id,
          trigger_websocket_watermark: stablePreTrigger.watermark },
        { ...traceSnapshot(staleSnapshot), connection_state: 'STALE', kind: 'stale', order: '2' },
        { ...traceSnapshot(resynchronizingSnapshot), connection_state: 'RESYNCHRONIZING',
          kind: 'resynchronizing', order: '3' },
        { ...stablePostDom, connection_state: 'LIVE', kind: 'stable_post_restart',
          state_bounds: stablePostStateBounds, order: '4', screenshot: 'screenshots/stable-post-restart.png',
          screenshot_sha256: sha256(stablePostScreenshot),
          trigger_websocket_order: stablePostTrigger.order,
          trigger_websocket_socket_id: stablePostTrigger.socket_id,
          trigger_websocket_watermark: stablePostTrigger.watermark },
      ],
      document_id: retainedDocumentId,
      page_instance_id: pageInstanceId,
      schema_version: 1,
      selection,
    }))],
    ['http/stable-post-restart.json', 'application/json', stablePostBody],
    ['http/stable-pre-restart.json', 'application/json', stablePreBody],
    ['http/unknown.json', 'application/json', unknownBody],
    ['screenshots/stable-post-restart.png', 'image/png', stablePostScreenshot],
    ['screenshots/stable-pre-restart.png', 'image/png', stablePreScreenshot],
    ['screenshots/unknown.png', 'image/png', unknownScreenshot],
    ['websocket.json', 'application/json', Buffer.from(canonicalJson({
      events: websocketEvents,
      schema_version: 1,
      url: retainedWebSocketUrl,
    }))],
  ];
  budget.validateArtifacts(artifacts);
  artifacts.sort(([left], [right]) => Buffer.from(left).compare(Buffer.from(right)));
  for (const [path, , bytes] of artifacts) await writeNew(join(root, path), bytes);
  const dimensions = await page.evaluate(() => ({
    height: window.innerHeight,
    width: window.innerWidth,
  }));
  const scale = await page.evaluate(() => window.devicePixelRatio.toString());
  const endedUtcNs = clock.utcNowNs();
  const observer = {
    artifacts: artifacts.map(([path, mediaType, bytes]) => ({
      media_type: mediaType,
      path,
      sha256: sha256(bytes),
    })),
    browser: {
      application_id: browserIdentity.application_id,
      executable_sha256: browserIdentity.executable_sha256,
      name: browserIdentity.name,
      team_id: browserIdentity.team_id,
      version: browserIdentity.version,
    },
    environment: 'local_production',
    interval: { ended_utc_ns: endedUtcNs.toString(), started_utc_ns: startedUtcNs.toString() },
    page_instance_id: pageInstanceId,
    schema_version: 1,
    selection,
    served_asset_sha256: servedAssetSha256(servedAssetResponses),
    viewport: {
      device_scale_factor: scale,
      height: String(dimensions.height),
      width: String(dimensions.width),
    },
  };
  await writeNew(join(root, 'observer.json'), Buffer.from(canonicalJson(observer)));
  finished = true;
  await new Promise((resolve) => process.stdout.write(
    `${canonicalJson({ page_instance_id: pageInstanceId, result: 'captured' })}\n`,
    resolve,
  ));
} finally {
  finished = true;
}
})();
try {
  return await Promise.race([operation, timeoutFailure]);
} finally {
  clearTimeout(observerTimer);
}
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await observe(systemObserverClock());
  process.exit(0);
}
