import { chromium, expect, test } from '@playwright/test';
import { createCipheriv, createHash } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { execFile, spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

import {
  chromeIdentity,
  observe,
  ObserverRetentionBudget,
  observerTiming,
  productionLiveWebSocketUrl,
  servedAssetSha256,
  screenshotState,
  signedChromeApplication,
} from '../../scripts/evidence-observer.mjs';

const execFileAsync = promisify(execFile);
const profile = '61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2';
const key = Buffer.alloc(32, 0x11);
const csiFrameIntervalMs = 50;
const csiFrameIntervalUs = 50_000;
// The simulated RF stream shares one event loop with Chrome orchestration. A 500 ms fixture-only
// receive-jitter allowance prevents host scheduling pauses from fabricating an RF quality change.
const simulatedReceiveJitterBudgetNs = 500_000_000;

test('evidence observer timing uses an injected monotonic and UTC clock', () => {
  const timing = observerTiming({ monotonicNowMs: () => 25, utcNowNs: () => 30n }, 100);
  expect(timing).toEqual({ deadlineMs: 125, startedUtcNs: 30n });
  expect(() => observerTiming({
    monotonicNowMs: () => { throw new Error('clock unavailable'); },
    utcNowNs: () => 30n,
  }, 100)).toThrow('clock unavailable');
  expect(() => observerTiming({ monotonicNowMs: () => 0, utcNowNs: () => 0n }, 120_001))
    .toThrow('observer timeout exceeds its bounded maximum');
});

test('evidence observer applies one total deadline while Chrome identity is unavailable', async () => {
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const port = server.address().port;
  const clock = {
    monotonicNowMs: () => performance.now(),
    sleep: (milliseconds) => new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds)),
    utcNowNs: () => BigInt(Date.now()) * 1_000_000n,
  };
  try {
    await expect(observe(clock, [
      '/unused',
      `cdp:http://127.0.0.1:${port}`,
      'http://127.0.0.1:9001/',
      'deadline-page',
      '50',
    ])).rejects.toThrow('total deadline');
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolveClose) => server.close(resolveClose));
  }
});

test('evidence observer derives only the production loopback live WebSocket', () => {
  expect(productionLiveWebSocketUrl('http://127.0.0.1:9001/'))
    .toBe('ws://127.0.0.1:9001/api/live');
  expect(() => productionLiveWebSocketUrl('http://192.0.2.10:9001/'))
    .toThrow('loopback');
  expect(() => productionLiveWebSocketUrl('file:///tmp/index.html'))
    .toThrow('HTTP');
});

test('evidence observer bounds WebSocket and HTTP retention before package sealing', () => {
  const budget = new ObserverRetentionBudget();
  expect(() => budget.recordWebSocketEvent(65_537)).toThrow('WebSocket frame exceeds');
  budget.reserveHttpResponse();
  expect(() => budget.beginHttpResponse(null)).toThrow('Content-Length');
  expect(() => budget.beginHttpResponse(String(1024 * 1024 + 1)))
    .toThrow('HTTP response exceeds');
  const expected = budget.beginHttpResponse('12');
  expect(() => budget.finishHttpResponse(expected, 13)).toThrow('Content-Length');
  budget.releaseHttpResponse();
  for (let index = 0; index < 16; index += 1) budget.reserveHttpResponse();
  expect(() => budget.reserveHttpResponse()).toThrow('pending HTTP response count exceeds');
  for (let index = 0; index < 16; index += 1) budget.releaseHttpResponse();
});

test('served asset identity is derived from exact response paths and bytes', () => {
  expect(servedAssetSha256(new Map([
    ['/', Buffer.from('page')],
    ['/assets/app.js', Buffer.from('script')],
    ['/assets/app.css', Buffer.from('style')],
  ]))).toBe('a344377c1053e4a7cefd9d5232947d3028c23271d0382e0ec9af5b6fd54ff571');
  expect(() => servedAssetSha256(new Map([
    ['/assets/app.js', Buffer.from('script')],
  ]))).toThrow('served asset response set is incomplete');
});

test('evidence observer accepts Chrome and rejects Chromium identity', async () => {
  const response = (Browser) => async () => ({ ok: true, json: async () => ({ Browser }) });
  const official = async () => ({
    application_id: 'com.google.Chrome',
    executable_sha256: 'ab'.repeat(32),
    signature_verified: true,
    team_id: 'EQHXZ8M8AV',
  });
  await expect(chromeIdentity(
    'cdp:http://127.0.0.1:9222', response('Chrome/151.0.0.0'), official,
  )).resolves.toEqual({
    application_id: 'com.google.Chrome',
    endpoint: 'http://127.0.0.1:9222',
    executable_sha256: 'ab'.repeat(32),
    name: 'Chrome',
    team_id: 'EQHXZ8M8AV',
    version: '151.0.0.0',
  });
  await expect(chromeIdentity(
    'cdp:http://127.0.0.1:9222', response('Chromium/151.0.0.0'), official,
  ))
    .rejects.toThrow('not Google Chrome');
  await expect(chromeIdentity(
    'cdp:http://127.0.0.1:9222', response('Chrome/151.0.0.0'),
    async () => ({ application_id: 'org.chromium.Chromium', team_id: '-', executable_sha256: 'cd'.repeat(32) }),
  )).rejects.toThrow('not the signed Google Chrome application');
  await expect(chromeIdentity(
    'cdp:http://127.0.0.1:9222', response('Chrome/151.0.0.0'),
    async () => ({
      application_id: 'com.google.Chrome',
      executable_sha256: 'cd'.repeat(32),
      signature_verified: false,
      team_id: 'EQHXZ8M8AV',
    }),
  )).rejects.toThrow('not the signed Google Chrome application');
});

test('evidence observer cryptographically verifies the Chrome application bundle', async () => {
  const commands = [];
  const run = async (command, args) => {
    commands.push([command, args]);
    if (command === 'lsof') return { stdout: 'p123\n', stderr: '' };
    if (command === 'ps') {
      return {
        stdout: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n',
        stderr: '',
      };
    }
    if (args.includes('--verify')) return { stdout: '', stderr: '' };
    return {
      stdout: '',
      stderr: 'Identifier=com.google.Chrome\nTeamIdentifier=EQHXZ8M8AV\n',
    };
  };
  const identity = await signedChromeApplication(
    'http://127.0.0.1:9222',
    run,
    async () => 'ab'.repeat(32),
  );
  expect(identity.signature_verified).toBe(true);
  expect(commands).toContainEqual([
    'codesign',
    [
      '--verify',
      '--verbose=4',
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    ],
  ]);
});

test('evidence screenshot stability includes visible DOM text', () => {
  const baseline = { knowledge: 'stable', visible_text: ['Stable'] };
  expect(screenshotState(baseline)).not.toEqual(
    screenshotState({ ...baseline, visible_text: ['operator-secret-token'] }),
  );
});

function delay(milliseconds) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

async function freePort() {
  const server = createServer();
  await new Promise((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const { port } = server.address();
  await new Promise((resolveClose, reject) => server.close((error) => (
    error ? reject(error) : resolveClose()
  )));
  return port;
}

function capabilityBody(firmwareByte, abiByte, datagramBudgetBytes) {
  const descriptor = Buffer.alloc(79);
  Buffer.from([1, 1, 1, 1, 1, 1, 1, 32, 0x07]).copy(descriptor);
  descriptor.writeUInt16LE(612, 9);
  descriptor.writeUInt16LE(705, 11);
  descriptor.writeUInt16LE(datagramBudgetBytes, 13);
  descriptor.fill(firmwareByte, 15, 47);
  descriptor.fill(abiByte, 47);
  const digest = createHash('sha256').update(descriptor).digest();
  const length = Buffer.alloc(2);
  length.writeUInt16LE(descriptor.length);
  return Buffer.concat([digest, length, descriptor]);
}

function csiBody(capabilityDigest, captureSequence, timestampUs) {
  const body = Buffer.alloc(77);
  capabilityDigest.copy(body, 0);
  body.writeBigUInt64LE(BigInt(captureSequence), 32);
  body.writeUInt32LE(timestampUs, 40);
  body.writeBigUInt64LE(BigInt(timestampUs), 44);
  Buffer.from([2, 0, 0, 0, 0, 10]).copy(body, 52);
  Buffer.from([1, 0, 1, 1, 0, 214, 161, 6, 0, 0]).copy(body, 58);
  Buffer.from([0, 0, 1]).copy(body, 68);
  body.writeUInt16LE(6, 71);
  body.writeUInt16LE(3, 73);
  Buffer.from([1, 0]).copy(body, 75);
  const tail = Buffer.alloc(10);
  tail.writeUInt16LE(3, 0);
  tail.writeUInt16LE(0, 2);
  Buffer.from([1, 2, 3, 4, 5, 6]).copy(tail, 4);
  return Buffer.concat([body, tail]);
}

function sealNativeFrame(kind, messageSequence, body) {
  const header = Buffer.alloc(32);
  header[0] = 1;
  header[1] = kind;
  header.writeUInt16LE(header.length, 2);
  header.writeBigUInt64LE(1n, 4);
  header.writeUInt16LE(1, 12);
  header.writeUInt32LE(1, 16);
  header.writeBigUInt64LE(BigInt(messageSequence), 20);
  header.writeUInt16LE(body.length, 28);
  const nonce = Buffer.alloc(12);
  nonce.writeUInt32LE(1, 0);
  nonce.writeBigUInt64LE(BigInt(messageSequence), 4);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(header);
  return Buffer.concat([header, cipher.update(body), cipher.final(), cipher.getAuthTag()]);
}

async function udpSend(socket, port, bytes) {
  await new Promise((resolveSend, reject) => {
    socket.send(bytes, port, '127.0.0.1', (error) => (error ? reject(error) : resolveSend()));
  });
}

async function startHost(binary, configPath) {
  const child = spawn(binary, ['serve', configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  const exited = new Promise((resolveExit) => child.once('exit', (code, signal) => {
    resolveExit({ code, signal });
  }));
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const started = new Promise((resolveStarted, reject) => {
    const timeout = setTimeout(() => reject(new Error(`Host startup timed out: ${stderr}`)), 5000);
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      const match = stdout.match(/Host runtime started: capture=([^ ]+) http=([^\n]+)/);
      if (match) {
        clearTimeout(timeout);
        resolveStarted({ capture: match[1], http: match[2].trim() });
      }
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timeout);
      reject(new Error(`Host exited before startup: code=${code} signal=${signal} ${stderr}`));
    });
  });
  let addresses;
  try {
    addresses = await started;
  } catch (error) {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
    throw error;
  }
  return { child, addresses, exited, stderr: () => stderr };
}

async function stopHost(host) {
  if (host.child.exitCode === null && host.child.signalCode === null) {
    if (!host.child.kill('SIGINT')) throw new Error(`Host did not accept SIGINT: ${host.stderr()}`);
  }
  let result;
  try {
    result = await Promise.race([
      host.exited,
      delay(5000).then(() => { throw new Error(`Host shutdown timed out: ${host.stderr()}`); }),
    ]);
  } catch (error) {
    if (host.child.exitCode === null && host.child.signalCode === null) host.child.kill('SIGKILL');
    await host.exited;
    throw error;
  }
  if (result.code !== 0) {
    throw new Error(`Host shutdown failed: ${JSON.stringify(result)} ${host.stderr()}`);
  }
}

async function jsonGet(baseUrl, path) {
  const response = await fetch(`${baseUrl}${path}`);
  if (!response.ok) throw new Error(`GET ${path} returned ${response.status}`);
  return response.json();
}

async function waitFor(getValue, accept, label, attempts = 200) {
  let last;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      last = await getValue();
      if (accept(last)) return last;
    } catch (error) {
      last = error;
    }
    await delay(25);
  }
  const detail = last instanceof Error ? String(last) : JSON.stringify(last);
  throw new Error(`${label} did not become ready: ${detail}`);
}

async function relationshipLatest(baseUrl) {
  const subjects = await jsonGet(baseUrl, '/api/relationships/latest');
  const subject = subjects.data.subjects[0];
  if (!subject) return null;
  const query = new URLSearchParams({
    session: subject.session_id,
    link: subject.link,
    profile: subject.profile,
  });
  return jsonGet(baseUrl, `/api/relationships/latest?${query}`);
}

async function sendCommand(baseUrl, command) {
  const response = await fetch(`${baseUrl}/api/relationships/commands`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      http_schema_version: 1,
      target: { link: 'link-a', profile },
      command,
    }),
  });
  if (response.status !== 202) throw new Error(`command ${command} returned ${response.status}`);
}

function createPhysicalStream(socket, capturePort) {
  const capability = capabilityBody(0x01, 0x22, 1024);
  let messageSequence = 0;
  let captureSequence = 0;
  let timestampUs = 0;
  let csiStream = null;
  return {
    capability,
    captureSequence: () => captureSequence,
    async sendCapability() {
      messageSequence += 1;
      await udpSend(socket, capturePort, sealNativeFrame(1, messageSequence, capability));
    },
    async start() {
      if (csiStream) throw new Error('CSI stream is already running');
      const stream = { stopping: false, done: null };
      stream.done = (async () => {
        while (!stream.stopping) {
          messageSequence += 1;
          captureSequence += 1;
          timestampUs += csiFrameIntervalUs;
          const body = csiBody(capability.subarray(0, 32), captureSequence, timestampUs);
          await udpSend(socket, capturePort, sealNativeFrame(2, messageSequence, body));
          await delay(csiFrameIntervalMs);
        }
      })();
      csiStream = stream;
    },
    async stop() {
      if (!csiStream) return;
      const stream = csiStream;
      csiStream = null;
      stream.stopping = true;
      await stream.done;
    },
  };
}

async function writeHostFixtureConfig(root, httpPort, capturePort, capability) {
  const managed = join(root, 'managed');
  const secrets = join(root, 'secrets');
  const configPath = join(root, 'host.toml');
  const database = join(managed, 'host.sqlite3');
  await mkdir(managed, { mode: 0o700 });
  await mkdir(secrets, { mode: 0o700 });
  for (const [device, byte] of [[1, 0x11], [2, 0x22]]) {
    const directory = join(secrets, `device-${device}`);
    await mkdir(directory, { mode: 0o700 });
    const path = join(directory, 'key-1.bin');
    await writeFile(path, Buffer.alloc(32, byte), { mode: 0o600 });
    await chmod(path, 0o600);
  }
  const firstCapability = capability.subarray(0, 32).toString('hex');
  const secondCapability = capabilityBody(0x03, 0x44, 2048).subarray(0, 32).toString('hex');
  const source = (await readFile('tests/fixtures/config/valid-two-esp32.toml', 'utf8'))
    .replace('0202020202020202020202020202020202020202020202020202020202020202', firstCapability)
    .replace('0404040404040404040404040404040404040404040404040404040404040404', secondCapability)
    .replaceAll('expected_peer_ip = "192.0.2.10"', 'expected_peer_ip = "127.0.0.1"')
    .replaceAll('expected_peer_ip = "192.0.2.11"', 'expected_peer_ip = "127.0.0.1"')
    .replace('peer = "192.0.2.10"', 'peer = "127.0.0.1"')
    .replace('peer = "192.0.2.11"', 'peer = "127.0.0.1"')
    .replace('bind = "127.0.0.1:9000"', `bind = "0.0.0.0:${capturePort}"`)
    .replace('bind = "127.0.0.1:8080"', `bind = "127.0.0.1:${httpPort}"`)
    .replace('secret_root = "./data/secrets"', `secret_root = "${secrets}"`)
    .replace('database_path = "./data/whisper.sqlite3"', `database_path = "${database}"`)
    .replace(
      'maximum_receive_jitter_ns = 100000000',
      `maximum_receive_jitter_ns = ${simulatedReceiveJitterBudgetNs}`,
    );
  await writeFile(configPath, source);
  return { configPath, database };
}

test('evidence observer waits through a committed valid non-target relationship state', async () => {
  test.setTimeout(40_000);
  const root = await mkdtemp(join(tmpdir(), 'whisper-observer-transient-browser-'));
  const httpPort = await freePort();
  const capturePort = await freePort();
  const chromeDebugPort = await freePort();
  const baseUrl = `http://127.0.0.1:${httpPort}`;
  const binary = resolve(process.env.CARGO_TARGET_DIR ?? 'target', 'debug', 'whisper');
  const socket = createSocket('udp4');
  const physical = createPhysicalStream(socket, capturePort);
  let host = null;
  let observer = null;
  let operatorContext = null;
  try {
    await execFileAsync('cargo', ['build']);
    const { configPath } = await writeHostFixtureConfig(
      root, httpPort, capturePort, physical.capability,
    );
    await execFileAsync(binary, ['init-admission', configPath]);
    host = await startHost(binary, configPath);
    operatorContext = await chromium.launchPersistentContext(join(root, 'chrome-profile'), {
      args: [`--remote-debugging-port=${chromeDebugPort}`],
      channel: 'chrome',
      headless: true,
      viewport: { width: 1440, height: 900 },
    });
    const page = operatorContext.pages()[0] ?? await operatorContext.newPage();
    const observerRoot = join(root, 'observer');
    await mkdir(observerRoot, { mode: 0o700 });
    const child = spawn(process.execPath, [
      resolve('scripts/evidence-observer.mjs'), observerRoot,
      `cdp:http://127.0.0.1:${chromeDebugPort}`, baseUrl, 'transient-page', '30000',
    ], { env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const exited = new Promise((resolveExit) => child.once('exit', (code, signal) => {
      resolveExit({ code, signal });
    }));
    observer = { child, exited };
    await Promise.race([
      waitFor(() => stdout, (output) => output.includes('"state":"ready"'), 'observer ready'),
      exited.then((result) => { throw new Error(`observer exited before ready: ${JSON.stringify(result)} ${stderr}`); }),
    ]);
    await page.goto(baseUrl);
    await page.getByRole('radio', { name: 'Sensing' }).check();
    await physical.sendCapability();
    await physical.start();
    await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => latest?.data?.knowledge?.reason === 'baseline_missing',
      'BaselineMissing relationship',
    );
    await expect(page.getByTestId('relationship-state')).toHaveText('Unknown(BaselineMissing)');
    let releasePageReads;
    const pageReadsBlocked = new Promise((resolveRelease) => { releasePageReads = resolveRelease; });
    await page.route('**/api/relationships/latest?*', async (route) => {
      if (route.request().headers()['x-observer-probe'] === '1') {
        await route.continue();
        return;
      }
      await pageReadsBlocked;
      await route.continue();
    });
    await sendCommand(baseUrl, 'begin_learning');
    await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => latest?.data?.knowledge?.reason === 'baseline_learning',
      'committed BaselineLearning relationship',
    );
    await physical.stop();
    await delay(100);
    const settledLearning = await relationshipLatest(baseUrl);
    expect(settledLearning?.data?.knowledge?.reason).toBe('baseline_learning');
    const query = new URLSearchParams({
      session: settledLearning.data.session_id,
      link: settledLearning.data.link,
      profile: settledLearning.data.profile,
    });
    await page.evaluate(async (url) => {
      const response = await fetch(url, {
        cache: 'no-store',
        headers: { accept: 'application/json', 'x-observer-probe': '1' },
      });
      await response.arrayBuffer();
    }, `${baseUrl}/api/relationships/latest?${query}`);
    await Promise.race([
      waitFor(
        () => stdout,
        (output) => output.includes('"state":"non-target-observed"'),
        'observer non-target DOM read',
      ),
      exited.then((result) => { throw new Error(`observer exited on non-target DOM: ${JSON.stringify(result)} ${stderr}`); }),
    ]);
    expect(child.exitCode).toBeNull();
    releasePageReads();
    await Promise.race([
      waitFor(
        () => stdout,
        (output) => output.includes('"state":"unknown-captured"'),
        'observer BaselineLearning capture',
      ),
      exited.then((result) => { throw new Error(`observer exited before target: ${JSON.stringify(result)} ${stderr}`); }),
    ]);
    expect(child.exitCode).toBeNull();
    await page.unroute('**/api/relationships/latest?*');
  } finally {
    await physical.stop();
    if (observer?.child.exitCode === null && observer.child.signalCode === null) {
      observer.child.kill('SIGKILL');
      await observer.exited;
    }
    if (host) await stopHost(host);
    if (operatorContext) await operatorContext.close();
    socket.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('one production Host restart keeps the actual served Sensing page and selection', async () => {
  test.setTimeout(60_000);
  const root = await mkdtemp(join(tmpdir(), 'whisper-host-restart-browser-'));
  const httpPort = await freePort();
  const capturePort = await freePort();
  const chromeDebugPort = await freePort();
  const baseUrl = `http://127.0.0.1:${httpPort}`;
  const binary = resolve(process.env.CARGO_TARGET_DIR ?? 'target', 'debug', 'whisper');
  const socket = createSocket('udp4');
  const physical = createPhysicalStream(socket, capturePort);
  let host = null;
  let observer = null;
  let operatorContext = null;

  try {
    await execFileAsync('cargo', ['build']);
    const { configPath } = await writeHostFixtureConfig(
      root, httpPort, capturePort, physical.capability,
    );
    await execFileAsync(binary, ['init-admission', configPath]);

    host = await startHost(binary, configPath);
    operatorContext = await chromium.launchPersistentContext(join(root, 'chrome-profile'), {
      args: [`--remote-debugging-port=${chromeDebugPort}`],
      channel: 'chrome',
      headless: true,
      viewport: { width: 1440, height: 900 },
    });
    const page = operatorContext.pages()[0] ?? await operatorContext.newPage();
    const observerRoot = join(root, 'observer');
    await mkdir(observerRoot, { mode: 0o700 });
    const observerChild = spawn(process.execPath, [
      resolve('scripts/evidence-observer.mjs'),
      observerRoot,
      `cdp:http://127.0.0.1:${chromeDebugPort}`,
      baseUrl,
      'production-restart-page',
      '55000',
    ], {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let observerStdout = '';
    let observerStderr = '';
    observerChild.stdout.on('data', (chunk) => { observerStdout += chunk; });
    observerChild.stderr.on('data', (chunk) => { observerStderr += chunk; });
    const observerExited = new Promise((resolveExit) => observerChild.once('exit', (code, signal) => {
      resolveExit({ code, signal });
    }));
    observer = { child: observerChild, exited: observerExited, stderr: () => observerStderr };
    await Promise.race([
      waitFor(
        async () => observerStdout,
        (output) => output.includes('"state":"ready"'),
        'separate evidence observer',
        800,
      ),
      observerExited.then((result) => {
        throw new Error(
          `evidence observer exited before ready: ${JSON.stringify(result)} ${observerStderr}`,
        );
      }),
    ]);
    await page.goto(baseUrl);
    await page.getByRole('radio', { name: 'Sensing' }).check();
    await sendCommand(baseUrl, 'begin_learning');
    await physical.sendCapability();
    await physical.start();
    const initialLearning = await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => latest?.data?.knowledge?.reason === 'baseline_learning',
      'BaselineLearning relationship',
    );
    await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
    await expect(page.getByTestId('relationship-state'))
      .toHaveText('Unknown(BaselineLearning)');
    const selectedSession = await page.getByLabel('Semantic Session').inputValue();
    const selectedLink = await page.getByLabel('Sensing Link').inputValue();
    const selectedProfile = await page.getByLabel('Sensing Profile').inputValue();
    await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => latest?.data?.knowledge?.reason === 'baseline_learning'
        && BigInt(latest.data.result_time) >= BigInt(initialLearning.data.result_time) + 15_000_000_000n,
      'mature BaselineLearning relationship',
      800,
    );
    await sendCommand(baseUrl, 'commit');
    const initialStable = await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => latest?.data?.knowledge?.value === 'stable',
      'Stable relationship',
    );
    await expect(page.getByTestId('relationship-state')).toHaveText('Stable');
    await expect(page.locator('#relationship-change-state'))
      .toHaveText('Unknown(BaselineLearning) → Stable');
    const projectionBeforeStableWindow = BigInt(
      initialStable.receipt.projection_commit.sequence,
    );
    const captureBeforeStableWindow = physical.captureSequence();
    let stableBefore = await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => latest?.data?.knowledge?.value === 'stable'
        && BigInt(latest.data.result_time) >= BigInt(initialStable.data.result_time) + 2_000_000_000n,
      'pre-stop eligible Stable window',
    );
    expect(stableBefore.data.most_recent_change).toEqual(initialStable.data.most_recent_change);
    await physical.stop();
    const sentStableFrames = BigInt(physical.captureSequence() - captureBeforeStableWindow);
    stableBefore = await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => BigInt(latest.receipt.projection_commit.sequence)
        >= projectionBeforeStableWindow + sentStableFrames,
      'fully processed pre-stop cursor',
    );
    expect(stableBefore.data.knowledge.value).toBe('stable');
    expect(stableBefore.data.most_recent_change).toEqual(initialStable.data.most_recent_change);
    await waitFor(
      async () => ({
        exit_code: observerChild.exitCode,
        stderr: observerStderr,
        stdout: observerStdout,
      }),
      (observerState) => observerState.stdout.includes(
        `"result_time":"${stableBefore.data.result_time}","state":"stable-pre-captured"`,
      ),
      'observer capture of fully processed pre-restart Stable',
      800,
    );
    const topologyBefore = await jsonGet(baseUrl, '/api/topology');
    expect(topologyBefore.data.sessions).toHaveLength(1);

    expect(selectedSession).toBe(stableBefore.data.session_id);
    await page.evaluate(() => {
      window.__restartObservations = [];
      const connection = document.querySelector('[data-testid="connection-state"]');
      const detail = document.querySelector('#connection-detail');
      const stale = document.querySelector('#stale-indicator');
      const record = () => window.__restartObservations.push({
        connection: connection.textContent,
        detail: detail.textContent,
        stale: !stale.hidden,
      });
      new MutationObserver(record).observe(document.querySelector('.connection-block'), {
        attributes: true, childList: true, subtree: true,
      });
      record();
    });

    await stopHost(host);
    host = null;
    await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
    await expect(page.getByText('Retained result · stale')).toBeVisible();

    host = await startHost(binary, configPath);
    const rebuilt = await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => latest?.data?.knowledge?.value === 'stable',
      'rebuilt Stable relationship',
    );
    expect(rebuilt.data).toEqual(stableBefore.data);
    expect(rebuilt.receipt.projection_commit.store_id)
      .toBe(stableBefore.receipt.projection_commit.store_id);
    expect(BigInt(rebuilt.receipt.projection_commit.sequence))
      .toBeGreaterThanOrEqual(BigInt(stableBefore.receipt.projection_commit.sequence));
    await physical.start();
    const stableAfter = await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => latest?.data?.knowledge?.value === 'stable'
        && BigInt(latest.data.result_time) >= BigInt(stableBefore.data.result_time) + 2_000_000_000n,
      'continued Stable relationship',
    );
    const topologyAfter = await jsonGet(baseUrl, '/api/topology');
    expect(topologyAfter.data.sessions).toHaveLength(2);
    expect(topologyAfter.receipt.projection_commit.store_id)
      .toBe(topologyBefore.receipt.projection_commit.store_id);
    expect(stableAfter.data.session_id).toBe(stableBefore.data.session_id);
    expect(stableAfter.data.most_recent_change).toEqual(stableBefore.data.most_recent_change);

    await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
    await expect(page.getByTestId('relationship-result-time'))
      .toHaveText(`${stableAfter.data.result_time} ns`);
    await expect(page.getByLabel('Semantic Session')).toHaveValue(selectedSession);
    await expect(page.getByLabel('Sensing Link')).toHaveValue(selectedLink);
    await expect(page.getByLabel('Sensing Profile')).toHaveValue(selectedProfile);
    const observations = await page.evaluate(() => window.__restartObservations);
    const staleIndex = observations.findIndex(
      (item) => item.connection === 'POLLING' && item.stale,
    );
    const resynchronizingIndex = observations.findIndex((item, index) => (
      index > staleIndex
      && item.detail === 'Watermark received · reading complete HTTP resources'
    ));
    const liveIndex = observations.findIndex((item, index) => (
      index > resynchronizingIndex && item.connection === 'LIVE' && !item.stale
    ));
    expect(staleIndex).toBeGreaterThanOrEqual(0);
    expect(resynchronizingIndex).toBeGreaterThan(staleIndex);
    expect(liveIndex).toBeGreaterThan(resynchronizingIndex);
    const observerResult = await observerExited;
    expect(observerResult, observerStderr).toEqual({ code: 0, signal: null });
    expect(observerStdout).toContain('"result":"captured"');
    const observerReceipt = JSON.parse(await readFile(join(observerRoot, 'observer.json'), 'utf8'));
    const observerTrace = JSON.parse(await readFile(join(observerRoot, 'chrome-trace.json'), 'utf8'));
    const observerWebSocket = JSON.parse(
      await readFile(join(observerRoot, 'websocket.json'), 'utf8'),
    );
    const observedUnknown = JSON.parse(await readFile(join(observerRoot, 'http/unknown.json'), 'utf8'));
    const observedStablePre = JSON.parse(
      await readFile(join(observerRoot, 'http/stable-pre-restart.json'), 'utf8'),
    );
    const observedStablePost = JSON.parse(
      await readFile(join(observerRoot, 'http/stable-post-restart.json'), 'utf8'),
    );
    expect(observerReceipt.page_instance_id).toBe('production-restart-page');
    expect(observerReceipt.browser.name).toBe('Chrome');
    expect(observerReceipt.browser.application_id).toBe('com.google.Chrome');
    expect(observerReceipt.browser.team_id).toBe('EQHXZ8M8AV');
    expect(observerReceipt.browser.executable_sha256).toMatch(/^[0-9a-f]{64}$/);
    const scale = Number(observerReceipt.viewport.device_scale_factor);
    const expectedScreenshotWidth = Number(observerReceipt.viewport.width) * scale;
    const expectedScreenshotHeight = Number(observerReceipt.viewport.height) * scale;
    expect(Number.isInteger(expectedScreenshotWidth)).toBe(true);
    expect(Number.isInteger(expectedScreenshotHeight)).toBe(true);
    for (const path of [
      'screenshots/unknown.png',
      'screenshots/stable-pre-restart.png',
      'screenshots/stable-post-restart.png',
    ]) {
      const screenshot = await readFile(join(observerRoot, path));
      expect(screenshot.subarray(0, 8)).toEqual(Buffer.from('\x89PNG\r\n\x1a\n', 'binary'));
      expect(screenshot.readUInt32BE(16)).toBe(expectedScreenshotWidth);
      expect(screenshot.readUInt32BE(20)).toBe(expectedScreenshotHeight);
      expect(screenshot[24]).toBe(8);
      expect(screenshot[25]).toBe(2);
    }
    expect(observerReceipt.artifacts.map((artifact) => artifact.path)).toEqual([
      'chrome-trace.json',
      'http/stable-post-restart.json',
      'http/stable-pre-restart.json',
      'http/unknown.json',
      'screenshots/stable-post-restart.png',
      'screenshots/stable-pre-restart.png',
      'screenshots/unknown.png',
      'websocket.json',
    ]);
    expect(observerTrace.events.map((event) => event.kind)).toEqual([
      'unknown',
      'stable_pre_restart',
      'stale',
      'resynchronizing',
      'stable_post_restart',
    ]);
    expect(observerTrace.document_id).toMatch(/^[0-9a-f]{64}$/);
    for (const event of observerTrace.events) {
      expect(event.document_id).toBe(observerTrace.document_id);
      expect(event.selection).toEqual(observerTrace.selection);
    }
    for (const event of [observerTrace.events[0], observerTrace.events[1], observerTrace.events[4]]) {
      expect(event.screenshot_sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(event.visible_text).toEqual(expect.any(Array));
      expect(event.opaque_visual_surfaces).toEqual([]);
    }
    expect(observerTrace.events[0]).toMatchObject({
      change_state: null,
      change_time: null,
      knowledge: 'unknown:baseline_learning',
      result_time: observedUnknown.data.result_time,
    });
    expect(observedUnknown.data.knowledge).toEqual({
      kind: 'unknown',
      reason: 'baseline_learning',
    });
    expect(observerTrace.events[1]).toMatchObject({
      change_state: 'Unknown(BaselineLearning) → Stable',
      change_time: observedStablePre.data.most_recent_change.changed_at,
      knowledge: 'stable',
      result_time: observedStablePre.data.result_time,
    });
    expect(observerTrace.events[4]).toMatchObject({
      change_state: 'Unknown(BaselineLearning) → Stable',
      change_time: observedStablePost.data.most_recent_change.changed_at,
      knowledge: 'stable',
      result_time: observedStablePost.data.result_time,
    });
    for (const [eventIndex, response] of [
      [1, observedStablePre],
      [4, observedStablePost],
    ]) {
      const event = observerTrace.events[eventIndex];
      const trigger = observerWebSocket.events[Number(event.trigger_websocket_order)];
      expect(trigger.kind).toBe('message');
      expect(event.trigger_websocket_watermark).toBe(response.data.creator_commit.sequence);
      expect(trigger.watermark).toBe(response.data.creator_commit.sequence);
    }
    expect(BigInt(observerTrace.events[4].result_time))
      .toBeGreaterThan(BigInt(observerTrace.events[1].result_time));
    observer = null;
  } finally {
    try {
      await physical.stop();
      if (host) await stopHost(host);
    } finally {
      if (observer?.child.exitCode === null && observer.child.signalCode === null) {
        observer.child.kill('SIGKILL');
        await observer.exited;
      }
      if (operatorContext) await operatorContext.close();
      socket.close();
      await rm(root, { recursive: true, force: true });
    }
  }
});
