import { expect, test } from '@playwright/test';
import { createCipheriv, createHash } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { execFile, spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const profile = '61971bc9476bdeacd7703e3516457df620147f73157cd1d4ad836fb9c7b74be2';
const key = Buffer.alloc(32, 0x11);
const csiFrameIntervalMs = 50;
const csiFrameIntervalUs = 50_000;

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

test('one production Host restart keeps the actual served Sensing page and selection', async ({ page }) => {
  test.setTimeout(60_000);
  const root = await mkdtemp(join(tmpdir(), 'whisper-host-restart-browser-'));
  const managed = join(root, 'managed');
  const secrets = join(root, 'secrets');
  const configPath = join(root, 'host.toml');
  const database = join(managed, 'host.sqlite3');
  const httpPort = await freePort();
  const capturePort = await freePort();
  const baseUrl = `http://127.0.0.1:${httpPort}`;
  const binary = resolve(process.env.CARGO_TARGET_DIR ?? 'target', 'debug', 'whisper');
  const socket = createSocket('udp4');
  let host = null;
  let messageSequence = 0;
  let captureSequence = 0;
  let timestampUs = 0;
  let csiStream = null;
  const capability = capabilityBody(0x01, 0x22, 1024);

  async function sendCapability() {
    messageSequence += 1;
    await udpSend(socket, capturePort, sealNativeFrame(1, messageSequence, capability));
  }

  async function startCsiStream() {
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
  }

  async function stopCsiStream() {
    if (!csiStream) return;
    const stream = csiStream;
    csiStream = null;
    stream.stopping = true;
    await stream.done;
  }

  try {
    await execFileAsync('cargo', ['build']);
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
      .replace('database_path = "./data/whisper.sqlite3"', `database_path = "${database}"`);
    await writeFile(configPath, source);
    await execFileAsync(binary, ['init-admission', configPath]);

    host = await startHost(binary, configPath);
    await page.goto(baseUrl);
    await page.getByRole('radio', { name: 'Sensing' }).check();
    await sendCommand(baseUrl, 'begin_learning');
    await sendCapability();
    await startCsiStream();
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
    let stableBefore = await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => latest?.data?.knowledge?.value === 'stable'
        && BigInt(latest.data.result_time) >= BigInt(initialStable.data.result_time) + 2_000_000_000n,
      'pre-stop eligible Stable window',
    );
    expect(stableBefore.data.most_recent_change).toEqual(initialStable.data.most_recent_change);
    const projectionBeforeTail = BigInt(stableBefore.receipt.projection_commit.sequence);
    const captureBeforeTail = captureSequence;
    await waitFor(
      async () => captureSequence,
      (sequence) => sequence >= captureBeforeTail + 6,
      'eligible pre-stop open window',
    );
    await stopCsiStream();
    const sentTailFrames = BigInt(captureSequence - captureBeforeTail);
    stableBefore = await waitFor(
      () => relationshipLatest(baseUrl),
      (latest) => BigInt(latest.receipt.projection_commit.sequence)
        >= projectionBeforeTail + sentTailFrames,
      'fully processed pre-stop cursor',
    );
    expect(stableBefore.data.knowledge.value).toBe('stable');
    expect(stableBefore.data.most_recent_change).toEqual(initialStable.data.most_recent_change);
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
    await startCsiStream();
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
  } finally {
    try {
      await stopCsiStream();
      if (host) await stopHost(host);
    } finally {
      socket.close();
      await rm(root, { recursive: true, force: true });
    }
  }
});
