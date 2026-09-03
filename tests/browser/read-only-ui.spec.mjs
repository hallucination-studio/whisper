import { expect, test } from '@playwright/test';
import {
  live,
  profiles,
  relationshipLatestFor,
  relationshipSubjects,
  semanticSessions,
  sessions,
  signalsFor,
  storeId,
  topology,
} from './responses.mjs';

test('switches between Capture Session signals and Semantic Session relationship sensing', async ({ page }) => {
  const relationshipRequests = [];
  await page.route('**/api/topology', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(topology) }),
  );
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(signalsFor(route.request().url())),
  }));
  await page.route('**/api/relationships/latest', (route) => {
    relationshipRequests.push(route.request().url());
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(relationshipSubjects),
    });
  });
  await page.route('**/api/relationships/latest?**', (route) => {
    relationshipRequests.push(route.request().url());
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(relationshipLatestFor(route.request().url())),
    });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));

  await page.goto('/');
  await expect(page.getByRole('radio', { name: 'Signal Lab' })).toBeChecked();
  await expect(page.getByLabel('Capture Session')).toBeVisible();
  await expect(page.getByTestId('tile-heading')).toBeVisible();

  await page.getByRole('radio', { name: 'Sensing' }).check();
  await expect(page.getByLabel('Capture Session')).toBeHidden();
  await expect(page.getByLabel('Semantic Session')).toBeVisible();
  await page.getByLabel('Semantic Session').selectOption(semanticSessions[1]);
  await page.getByLabel('Sensing Profile').selectOption(profiles[2]);

  await expect.poll(() => relationshipRequests.some((request) => {
    const query = new URL(request).searchParams;
    return query.get('session') === semanticSessions[1]
      && query.get('link') === 'link-b'
      && query.get('profile') === profiles[2];
  })).toBe(true);
  await expect(page.getByTestId('relationship-state')).toHaveText('Unknown(BaselineLearning)');
  await expect(page.getByTestId('relationship-result-time')).toHaveText('1000000000 ns');
  await expect(page.getByTestId('tile-heading')).toBeHidden();
  await expect(page.locator('button')).toHaveCount(0);
});

test('keeps the retained Sensing state on integral CSS pixel bounds', async ({ page }) => {
  let socket;
  await page.route('**/api/topology', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(topology) }),
  );
  await page.route('**/api/relationships/latest', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(relationshipSubjects),
  }));
  await page.route('**/api/relationships/latest?**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(relationshipLatestFor(route.request().url())),
  }));
  await page.routeWebSocket('**/api/live', (websocket) => {
    if (!socket) {
      socket = websocket;
      websocket.send(JSON.stringify(live));
    }
  });

  await page.goto('/');
  await page.getByRole('radio', { name: 'Sensing' }).check();
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.getByTestId('relationship-state')).toHaveText('Unknown(BaselineLearning)');
  const relationshipState = page.getByTestId('relationship-state');
  const liveBounds = await relationshipState.boundingBox();
  expect(Object.values(liveBounds).every(Number.isInteger)).toBe(true);
  expect(Object.values(liveBounds).every((value) => value > 0)).toBe(true);

  await socket.close();
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
  await expect(page.getByText('Retained result · stale')).toBeVisible();
  const staleBounds = await relationshipState.boundingBox();
  expect(Object.values(staleBounds).every(Number.isInteger)).toBe(true);
  expect(Object.values(staleBounds).every((value) => value > 0)).toBe(true);
});

test('same Sensing page renders the committed BaselineLearning to Stable change', async ({ page }) => {
  const pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  let stable = false;
  let socket;
  await page.route('**/api/topology', (route) => {
    const response = structuredClone(topology);
    response.receipt.projection_commit.sequence = stable ? '6' : '5';
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(signalsFor(route.request().url())),
  }));
  await page.route('**/api/relationships/latest', (route) => {
    const response = structuredClone(relationshipSubjects);
    response.receipt.projection_commit.sequence = stable ? '6' : '5';
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.route('**/api/relationships/latest?**', (route) => {
    const response = relationshipLatestFor(route.request().url(), storeId, stable ? '6' : '5');
    if (stable) {
      response.data.knowledge = { kind: 'known', value: 'stable' };
      response.data.result_time = '2000000000';
      response.data.most_recent_change = {
        previous: { kind: 'unknown', reason: 'baseline_learning' },
        current: { kind: 'known', value: 'stable' },
        changed_at: '2000000000',
      };
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.routeWebSocket('**/api/live', (websocket) => {
    socket = websocket;
    websocket.send(JSON.stringify(live));
  });

  await page.goto('/');
  await expect.poll(() => pageErrors).toEqual([]);
  await page.getByRole('radio', { name: 'Sensing' }).check();
  await expect(page.getByTestId('relationship-state')).toHaveText('Unknown(BaselineLearning)');
  await expect(page.locator('[data-testid="relationship-evidence-marker"]')).toHaveCount(0);

  stable = true;
  socket.send(JSON.stringify({
    ...live,
    delivery_sequence: '1',
    projection_commit: { store_id: storeId, sequence: '6' },
  }));
  await expect(page.getByTestId('relationship-state')).toHaveText('Stable');
  await expect(page.getByTestId('relationship-result-time')).toHaveText('2000000000 ns');
  await expect(page.locator('#relationship-change-state'))
    .toHaveText('Unknown(BaselineLearning) → Stable');
  await expect(page.locator('#relationship-change-time')).toHaveText('2000000000 ns');
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
});

test('mounts a complete Sensing read while newer watermarks continue arriving', async ({ page }) => {
  let sequence = 5;
  let stable = false;
  let delayReads = false;
  let socket;
  const blockedTopologyReads = [];
  const blockNextTopologyRead = () => {
    let markStarted;
    let release;
    const started = new Promise((resolve) => { markStarted = resolve; });
    const released = new Promise((resolve) => { release = resolve; });
    blockedTopologyReads.push({ markStarted, released });
    return { started, release };
  };
  await page.route('**/api/topology', async (route) => {
    const response = structuredClone(topology);
    const responseSequence = String(sequence);
    response.receipt.projection_commit.sequence = responseSequence;
    if (delayReads) {
      const blockedRead = blockedTopologyReads.shift();
      expect(blockedRead).toBeDefined();
      blockedRead.markStarted();
      await blockedRead.released;
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.route('**/api/relationships/latest', async (route) => {
    const response = structuredClone(relationshipSubjects);
    const responseSequence = String(sequence);
    response.receipt.projection_commit.sequence = responseSequence;
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.route('**/api/relationships/latest?**', async (route) => {
    const responseSequence = String(sequence);
    const response = relationshipLatestFor(route.request().url(), storeId, responseSequence);
    if (stable) {
      response.data.knowledge = { kind: 'known', value: 'stable' };
      response.data.result_time = '2000000000';
      response.data.most_recent_change = {
        previous: { kind: 'unknown', reason: 'baseline_learning' },
        current: { kind: 'known', value: 'stable' },
        changed_at: '2000000000',
      };
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.routeWebSocket('**/api/live', (websocket) => {
    socket = websocket;
    websocket.send(JSON.stringify(live));
  });

  await page.goto('/');
  await page.getByRole('radio', { name: 'Sensing' }).check();
  await expect(page.getByTestId('relationship-state')).toHaveText('Unknown(BaselineLearning)');

  stable = true;
  delayReads = true;
  const firstRead = blockNextTopologyRead();
  sequence = 6;
  socket.send(JSON.stringify({
    ...live,
    delivery_sequence: '1',
    projection_commit: { store_id: storeId, sequence: '6' },
  }));
  await firstRead.started;

  const followUpRead = blockNextTopologyRead();
  sequence = 7;
  socket.send(JSON.stringify({
    ...live,
    delivery_sequence: '2',
    projection_commit: { store_id: storeId, sequence: '7' },
  }));
  firstRead.release();
  await followUpRead.started;

  await expect(page.getByTestId('relationship-state')).toHaveText('Stable');
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
  followUpRead.release();
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
});

test('rejects a relationship response outside the closed HTTP schema', async ({ page }) => {
  await page.route('**/api/topology', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(topology) }),
  );
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(signalsFor(route.request().url())),
  }));
  await page.route('**/api/relationships/latest', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(relationshipSubjects),
  }));
  await page.route('**/api/relationships/latest?**', (route) => {
    const response = relationshipLatestFor(route.request().url());
    response.data.command = 'begin_learning';
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));

  await page.goto('/');
  await page.getByRole('radio', { name: 'Sensing' }).check();
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('relationship-state')).toBeHidden();
  await expect(page.locator('button')).toHaveCount(0);
});

test('rejects legacy and malformed known Knowledge without mounting relationship state', async ({ page }) => {
  let knowledge;
  await page.route('**/api/topology', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(topology) }),
  );
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(signalsFor(route.request().url())),
  }));
  await page.route('**/api/relationships/latest', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(relationshipSubjects),
  }));
  await page.route('**/api/relationships/latest?**', (route) => {
    const response = relationshipLatestFor(route.request().url());
    response.data.knowledge = knowledge;
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(response),
    });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));

  for (const [label, invalidKnowledge] of [
    ['legacy Stable', { kind: 'stable' }],
    ['legacy Changing', { kind: 'changing' }],
    ['missing known value', { kind: 'known' }],
    ['invalid known value', { kind: 'known', value: 'unknown' }],
    ['extra known property', { kind: 'known', value: 'stable', extra: true }],
  ]) {
    await test.step(label, async () => {
      knowledge = invalidKnowledge;
      await page.goto('/');
      await page.getByRole('radio', { name: 'Sensing' }).check();
      await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
      await expect(page.getByTestId('relationship-state')).toBeHidden();
      await expect(page.locator('#relationship-change')).toBeHidden();
    });
  }
});

test('keeps Sensing POLLING until every relationship receipt reaches the WebSocket watermark', async ({ page }) => {
  let sequence = '5';
  const currentTopology = structuredClone(topology);
  currentTopology.receipt.projection_commit.sequence = '6';
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(currentTopology),
  }));
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(signalsFor(route.request().url(), storeId, '6')),
  }));
  await page.route('**/api/relationships/latest', (route) => {
    const response = structuredClone(relationshipSubjects);
    response.receipt.projection_commit.sequence = sequence;
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.route('**/api/relationships/latest?**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(relationshipLatestFor(route.request().url(), storeId, sequence)),
  }));
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify({
    ...live,
    projection_commit: { store_id: storeId, sequence: '6' },
  })));

  await page.goto('/');
  await page.getByRole('radio', { name: 'Sensing' }).check();
  await expect(page.getByTestId('relationship-state')).toHaveText('Unknown(BaselineLearning)');
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
  await page.waitForTimeout(300);
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');

  sequence = '6';
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
});

test('selects and renders a non-first session, Sensor, Link, and Profile', async ({ page }) => {
  const signalRequests = [];
  await page.route('**/api/topology', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(topology) }),
  );
  await page.route('**/api/signals?**', (route) => {
    signalRequests.push(route.request().url());
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(signalsFor(route.request().url())),
    });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));

  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.getByLabel('Capture Session')).toHaveCount(1);
  await expect(page.getByLabel('Sensor').locator('option')).toHaveCount(2);

  await page.getByLabel('Capture Session').selectOption(sessions[1]);
  await page.getByLabel('Sensor').selectOption('sensor-b');
  await page.locator('#link-select').selectOption('link-b');
  await page.locator('#profile-select').selectOption(profiles[2]);

  await expect.poll(() => signalRequests.some((request) => {
    const query = new URL(request).searchParams;
    return query.get('session') === sessions[1]
      && query.get('sensor') === 'sensor-b'
      && query.get('link') === 'link-b'
      && query.get('profile') === profiles[2];
  })).toBe(true);
  await expect(page.getByTestId('tile-heading')).toContainText('sensor-b · link-b');
  await expect(page.getByText('Opaque sample ordinal 0')).toBeVisible();
  await expect(page.getByLabel('Measured zero')).toBeVisible();
  await expect(page.getByLabel('Missing value').first()).toBeVisible();
  await expect(page.locator('.signal-grid tbody th[scope="row"]')).toHaveCount(2);
});

test('unmounts retained cells while a changed selection is still loading', async ({ page }) => {
  let delaySignals = false;
  let signalStarted;
  let releaseSignal;
  const changedSignalStarted = new Promise((resolve) => { signalStarted = resolve; });
  const changedSignalRelease = new Promise((resolve) => { releaseSignal = resolve; });
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', async (route) => {
    if (delaySignals) {
      signalStarted();
      await changedSignalRelease;
    }
    return route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify(signalsFor(route.request().url())),
    });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.getByTestId('tile-heading')).toBeVisible();

  delaySignals = true;
  await page.getByLabel('Metric').selectOption('q');
  await changedSignalStarted;
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
  await expect(page.getByText('Selection changed. Reading a complete signals resource…')).toBeVisible();
  await expect(page.getByText('Retained result · stale')).toBeHidden();
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);

  releaseSignal();
  await expect(page.getByText('Retained result · stale')).toBeHidden();
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
});

test('requests an explicit interval, metric, and applicable native path', async ({ page }) => {
  const signalRequests = [];
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => {
    signalRequests.push(route.request().url());
    return route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify(signalsFor(route.request().url())),
    });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');

  await page.getByLabel('Metric').selectOption('amplitude');
  await page.getByLabel('Interval from (ns)').fill('10');
  await page.getByLabel('Interval from (ns)').press('Tab');
  await page.getByLabel('Interval to (ns)').fill('40');
  await page.getByLabel('Interval to (ns)').press('Tab');
  await page.locator('#path-select').selectOption({ label: 'Raw path ordinal 0' });

  await expect.poll(() => signalRequests.some((request) => {
    const query = new URL(request).searchParams;
    return query.get('metric') === 'amplitude' && query.get('from') === '10'
      && query.get('to') === '40' && query.get('path') === 'raw_path_ordinal:0';
  })).toBe(true);
  await expect(page.locator('.aggregate').first()).toContainText('mean0');
  await expect(page.getByLabel('Missing value').first()).toBeVisible();
});

test('polls visibly with stale retained data, then resynchronizes before LIVE', async ({ page }) => {
  let failPolls = false;
  const sockets = [];
  await page.route('**/api/topology', (route) => failPolls
    ? route.abort('failed')
    : route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(topology) }));
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(signalsFor(route.request().url())),
  }));
  await page.routeWebSocket('**/api/live', (socket) => {
    sockets.push(socket);
    socket.send(JSON.stringify(live));
  });

  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.getByTestId('tile-heading')).toBeVisible();
  failPolls = true;
  await sockets[0].close();

  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
  await expect(page.getByText('Retained result · stale')).toBeVisible();
  await expect(page.getByTestId('tile-heading')).toBeVisible();
  await page.waitForTimeout(300);
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');

  failPolls = false;
  await expect.poll(() => sockets.length).toBeGreaterThan(1);
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.getByText('Retained result · stale')).toBeHidden();
});

test('cannot return to LIVE from HTTP polling while the WebSocket is closed', async ({ page }) => {
  let socket;
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(signalsFor(route.request().url())),
  }));
  await page.routeWebSocket('**/api/live', (websocket) => {
    if (!socket) {
      socket = websocket;
      websocket.send(JSON.stringify(live));
    }
  });
  await page.goto('/');
  const connection = page.getByTestId('connection-state');
  await expect(connection).toHaveText('LIVE');
  await expect(connection).toHaveAttribute('data-mode', 'live');
  const liveColor = await connection.evaluate((element) => getComputedStyle(element).color);
  await socket.close();
  await page.waitForTimeout(300);
  await expect(connection).toHaveText('POLLING');
  await expect(connection).toHaveAttribute('data-mode', 'polling');
  await expect.poll(() => connection.evaluate((element) => getComputedStyle(element).color)).not.toBe(liveColor);
  await expect(page.getByTestId('tile-heading')).toBeVisible();
});

test('discards retained context when the Store ID changes', async ({ page }) => {
  const nextStoreId = 'cd'.repeat(32);
  const nextProfile = '44'.repeat(32);
  const nextSession = 'capture-00000000000000000000000000000003';
  const nextTopology = structuredClone(topology);
  nextTopology.receipt.projection_commit = { store_id: nextStoreId, sequence: '1' };
  nextTopology.data.sessions = [nextSession];
  nextTopology.data.sensors = [{ id: 'sensor-z', hardware_kind: 'esp32-s3', device_id: '9' }];
  nextTopology.data.links = [{
    id: 'link-z', space: 'room', transmitter: 'tx-z', receiver: 'sensor-z', profiles: [nextProfile],
  }];
  let activeTopology = topology;
  let activeStore = storeId;
  let activeSequence = '5';
  let delayNextTopology = false;
  let topologyStarted;
  let releaseTopology;
  const nextTopologyStarted = new Promise((resolve) => { topologyStarted = resolve; });
  const nextTopologyRelease = new Promise((resolve) => { releaseTopology = resolve; });
  let socket;
  await page.route('**/api/topology', async (route) => {
    if (delayNextTopology && activeTopology === nextTopology) {
      topologyStarted();
      await nextTopologyRelease;
    }
    return route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify(activeTopology),
    });
  });
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(signalsFor(route.request().url(), activeStore, activeSequence)),
  }));
  await page.routeWebSocket('**/api/live', (websocket) => {
    socket = websocket;
    websocket.send(JSON.stringify(live));
  });
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.getByTestId('tile-heading')).toContainText('sensor-a');

  activeTopology = nextTopology;
  activeStore = nextStoreId;
  activeSequence = '1';
  delayNextTopology = true;
  socket.send(JSON.stringify({
    ...live,
    delivery_sequence: '1',
    projection_commit: { store_id: nextStoreId, sequence: '1' },
  }));

  await nextTopologyStarted;
  await expect(page.locator('#deployment-id')).toHaveText('Not read');
  await expect(page.locator('#store-id')).toHaveText('Not read');
  await expect(page.locator('#watermark')).toHaveText('—');
  await expect(page.getByText('Retained result · stale')).toBeHidden();
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
  releaseTopology();

  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.locator('#store-id')).toHaveText(nextStoreId);
  await expect(page.getByLabel('Sensor').locator('option')).toHaveText(['sensor-z']);
  await expect(page.getByTestId('tile-heading')).toContainText('sensor-z · link-z');
  await expect(page.getByTestId('tile-heading')).not.toContainText('sensor-a');
});

test('stays POLLING until topology and signals receipts reach the WebSocket watermark', async ({ page }) => {
  let sequence = '5';
  await page.route('**/api/topology', (route) => {
    const response = structuredClone(topology);
    response.receipt.projection_commit.sequence = sequence;
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(signalsFor(route.request().url(), storeId, sequence)),
  }));
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify({
    ...live,
    projection_commit: { store_id: storeId, sequence: '6' },
  })));
  await page.goto('/');
  await expect(page.getByTestId('tile-heading')).toBeVisible();
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
  await page.waitForTimeout(300);
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');

  sequence = '6';
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
});

test('rejects duplicate JSON properties without mounting fabricated state', async ({ page }) => {
  const duplicate = JSON.stringify(topology).replace('"kind":"ok"', '"kind":"ok","kind":"ok"');
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: duplicate,
  }));
  await page.route('**/api/signals?**', (route) => route.abort());
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');

  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
  await expect(page.locator('button')).toHaveCount(0);
});

test('rejects an own __proto__ property as an unknown schema field', async ({ page }) => {
  const polluted = JSON.stringify(topology).replace('{"http_schema_version"', '{"__proto__":{"polluted":true},"http_schema_version"');
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: polluted,
  }));
  await page.route('**/api/signals?**', (route) => route.abort());
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
});

test('rejects non-JSON whitespace before a response root', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: `\u00a0${JSON.stringify(topology)}`,
  }));
  await page.route('**/api/signals?**', (route) => route.abort());
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
});

test('rejects topology collections that are not in strict UTF-8 byte order', async ({ page }) => {
  const unordered = structuredClone(topology);
  unordered.data.sessions.reverse();
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(unordered),
  }));
  await page.route('**/api/signals?**', (route) => route.abort());
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
});

test('rejects an identifier containing only imported Unicode whitespace', async ({ page }) => {
  const invalidIdentifier = structuredClone(topology);
  invalidIdentifier.data.deployment = '\u0085';
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(invalidIdentifier),
  }));
  await page.route('**/api/signals?**', (route) => route.abort());
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
});

test('rejects a response body that is not exact UTF-8', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: Buffer.from([0xff]),
  }));
  await page.route('**/api/signals?**', (route) => route.abort());
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
});

test('rejects an escaped lone surrogate in an identifier', async ({ page }) => {
  const invalidIdentifier = structuredClone(topology);
  invalidIdentifier.data.deployment = '\ud800';
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(invalidIdentifier),
  }));
  await page.route('**/api/signals?**', (route) => route.abort());
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
});

test('rejects a fractional numeric token that rounds to an integer DTO value', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => {
    const body = JSON.stringify(signalsFor(route.request().url()))
      .replace('"boot_generation":1', '"boot_generation":1.0000000000000000001');
    return route.fulfill({ status: 200, contentType: 'application/json', body });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
});

test('accepts equivalent JSON number spellings for exact integer DTO values', async ({ page }) => {
  await page.route('**/api/topology', (route) => {
    const body = JSON.stringify(topology).replace('"http_schema_version":1', '"http_schema_version":1.0');
    return route.fulfill({ status: 200, contentType: 'application/json', body });
  });
  await page.route('**/api/signals?**', (route) => {
    const body = JSON.stringify(signalsFor(route.request().url()))
      .replace('"boot_generation":1', '"boot_generation":100e-2');
    return route.fulfill({ status: 200, contentType: 'application/json', body });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.getByTestId('tile-heading')).toBeVisible();
});

test('rejects semantically duplicate native paths regardless of property order', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => {
    const response = signalsFor(route.request().url());
    const currentTile = response.data.tiles[0];
    currentTile.path_axis = [
      { kind: 'raw_path_ordinal', ordinal: 0 },
      { ordinal: 0, kind: 'raw_path_ordinal' },
    ];
    currentTile.cells = [...currentTile.cells, ...currentTile.cells];
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
});

test('rejects aggregate buckets in a raw tile', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => {
    const response = signalsFor(route.request().url());
    response.data.tiles[0].cells[0] = {
      kind: 'min_max_mean_rms_count', minimum: 0, maximum: 0, mean: 0, rms: 0, count: 1,
    };
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
});

test('rejects heterogeneous aggregation modes across signal tiles', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => {
    const response = signalsFor(route.request().url());
    const aggregateTile = structuredClone(response.data.tiles[0]);
    aggregateTile.stream.key.sensor = 'sensor-b';
    aggregateTile.stream.key.link = 'link-b';
    aggregateTile.stream.key.profile = profiles[1];
    aggregateTile.stream.device_epoch = { device_id: '2', boot_generation: 1 };
    aggregateTile.profile = profiles[1];
    aggregateTile.aggregation = 'min_max_mean_rms_count';
    aggregateTile.cells = aggregateTile.cells.map((cell) => cell === null ? null : ({
      kind: 'min_max_mean_rms_count',
      minimum: cell.value,
      maximum: cell.value,
      mean: cell.value,
      rms: Math.abs(cell.value),
      count: 1,
    }));
    response.data.tiles.push(aggregateTile);
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
});

test('rejects signal times outside the requested half-open interval', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => {
    const response = signalsFor(route.request().url());
    response.data.tiles[0].time_axis = [new URL(route.request().url()).searchParams.get('to')];
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
});

test('rejects a signals response for a different requested path', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => {
    const response = signalsFor(route.request().url());
    if (new URL(route.request().url()).searchParams.has('path')) {
      response.data.tiles[0].path_axis = [{ kind: 'raw_path_ordinal', ordinal: 1 }];
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await page.locator('#path-select').selectOption({ label: 'Raw path ordinal 0' });
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
});

test('rejects malformed error bodies and status-code mappings', async ({ page }) => {
  let errorResponse = {
    status: 400,
    body: { http_schema_version: 1, kind: 'error', error: { code: 'invalid_request', message: null } },
  };
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: errorResponse.status, contentType: 'application/json', body: JSON.stringify(errorResponse.body),
  }));
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');

  errorResponse = {
    status: 416,
    body: { http_schema_version: 1, kind: 'error', error: { code: 'invalid_request', message: 'invalid' } },
  };
  await page.reload();
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
});

test('rejects a signals-only error code returned by topology', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 416,
    contentType: 'application/json',
    body: JSON.stringify({
      http_schema_version: 1,
      kind: 'error',
      error: { code: 'range_unavailable', message: 'not applicable' },
    }),
  }));
  await page.route('**/api/signals?**', (route) => route.abort());
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
});

test('rejects a canonical body returned with a noncanonical success status', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 201, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => route.abort());
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
});

test('rejects BOM, noncanonical u64, negative zero, empty axes, and reversed receipts', async ({ page }) => {
  let topologyBody = JSON.stringify(topology);
  let signalMutation = null;
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: topologyBody,
  }));
  await page.route('**/api/signals?**', (route) => {
    const response = signalsFor(route.request().url());
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: signalMutation ? signalMutation(response) : JSON.stringify(response),
    });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));

  topologyBody = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(topology))]);
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');

  const noncanonical = structuredClone(topology);
  noncanonical.receipt.projection_commit.sequence = '01';
  topologyBody = JSON.stringify(noncanonical);
  await page.reload();
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');

  const outOfRange = structuredClone(topology);
  outOfRange.receipt.projection_commit.sequence = '18446744073709551616';
  topologyBody = JSON.stringify(outOfRange);
  await page.reload();
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');

  topologyBody = JSON.stringify(topology);
  signalMutation = (response) => JSON.stringify(response).replace('"value":0', '"value":-0');
  await page.reload();
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');

  signalMutation = (response) => {
    response.data.tiles[0].time_axis = [];
    response.data.tiles[0].cells = [];
    return JSON.stringify(response);
  };
  await page.reload();
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');

  signalMutation = (response) => {
    response.receipt.first_record_seq = '2';
    response.receipt.last_record_seq = '1';
    response.data.tiles[0].receipt = response.receipt;
    return JSON.stringify(response);
  };
  await page.reload();
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
});

test('returns to POLLING on close after recovering from a protocol error', async ({ page }) => {
  const sockets = [];
  let invalidTopology = true;
  await page.route('**/api/topology', (route) => {
    const response = structuredClone(topology);
    if (invalidTopology) response.kind = 'invalid';
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(signalsFor(route.request().url())),
  }));
  await page.routeWebSocket('**/api/live', (socket) => {
    sockets.push(socket);
    if (sockets.length === 1) socket.send('{"bad":true}');
  });
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');
  invalidTopology = false;
  await expect.poll(() => sockets.length).toBeGreaterThan(1);
  sockets.at(-1).send(JSON.stringify(live));
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await sockets.at(-1).close();
  await page.waitForTimeout(100);
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
});

test('returns to POLLING after valid HTTP recovery while the WebSocket stays closed', async ({ page }) => {
  let invalidTopology = true;
  await page.route('**/api/topology', (route) => {
    const response = structuredClone(topology);
    if (invalidTopology) response.kind = 'invalid';
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(signalsFor(route.request().url())),
  }));
  await page.routeWebSocket('**/api/live', (socket) => socket.close());
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('PROTOCOL ERROR');

  invalidTopology = false;
  await expect(page.getByTestId('tile-heading')).toBeVisible();
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
  await expect(page.getByTestId('connection-state')).toHaveAttribute('data-mode', 'polling');
});

test('accepts an equal half-open interval as a complete empty result', async ({ page }) => {
  const requests = [];
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => {
    requests.push(route.request().url());
    const populated = signalsFor(route.request().url());
    const query = new URL(route.request().url()).searchParams;
    const body = query.get('from') === query.get('to')
      ? { http_schema_version: 1, kind: 'empty', resource: 'signals', receipt: populated.receipt }
      : populated;
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await page.getByLabel('Interval from (ns)').fill('10');
  await page.getByLabel('Interval from (ns)').press('Tab');
  await page.getByLabel('Interval to (ns)').fill('10');
  await page.getByLabel('Interval to (ns)').press('Tab');
  await expect.poll(() => requests.some((request) => {
    const query = new URL(request).searchParams;
    return query.get('from') === '10' && query.get('to') === '10';
  })).toBe(true);
  await expect(page.getByText('No committed signal cells match this read context.')).toBeVisible();
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
});

test('clears mounted cells when topology removes every complete selection', async ({ page }) => {
  let currentTopology = topology;
  let socket;
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(currentTopology),
  }));
  await page.route('**/api/signals?**', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(signalsFor(route.request().url())),
  }));
  await page.routeWebSocket('**/api/live', (websocket) => {
    socket = websocket;
    websocket.send(JSON.stringify(live));
  });
  await page.goto('/');
  await expect(page.getByTestId('tile-heading')).toBeVisible();

  currentTopology = structuredClone(topology);
  currentTopology.receipt.projection_commit.sequence = '6';
  currentTopology.data.sessions = [];
  currentTopology.data.links.forEach((link) => { link.profiles = []; });
  socket.send(JSON.stringify({
    ...live,
    delivery_sequence: '1',
    projection_commit: { store_id: storeId, sequence: '6' },
  }));
  await expect(page.getByText('No committed Capture Session and Profile are available.')).toBeVisible();
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
  await expect(page.getByText('Retained result · stale')).toBeHidden();
});

test('stages topology selection changes until the paired signals read succeeds', async ({ page }) => {
  let currentTopology = topology;
  let failSignals = false;
  let socket;
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(currentTopology),
  }));
  await page.route('**/api/signals?**', (route) => failSignals
    ? route.abort('failed')
    : route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(signalsFor(
        route.request().url(), storeId, currentTopology.receipt.projection_commit.sequence,
      )),
    }));
  await page.routeWebSocket('**/api/live', (websocket) => {
    socket = websocket;
    websocket.send(JSON.stringify(live));
  });
  await page.goto('/');
  await expect(page.getByTestId('tile-heading')).toContainText('sensor-a');

  currentTopology = structuredClone(topology);
  currentTopology.receipt.projection_commit.sequence = '6';
  currentTopology.data.sensors = [currentTopology.data.sensors[1]];
  currentTopology.data.links = [currentTopology.data.links[1]];
  failSignals = true;
  socket.send(JSON.stringify({
    ...live,
    delivery_sequence: '1',
    projection_commit: { store_id: storeId, sequence: '6' },
  }));

  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
  await expect(page.getByLabel('Sensor')).toHaveValue('sensor-a');
  await expect(page.getByTestId('tile-heading')).toContainText('sensor-a');
  await expect(page.getByText('Retained result · stale')).toBeVisible();

  failSignals = false;
  await expect(page.getByLabel('Sensor')).toHaveValue('sensor-b');
  await expect(page.getByTestId('tile-heading')).toContainText('sensor-b · link-b');
  await expect(page.getByText('Retained result · stale')).toBeHidden();
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
});

test('cannot remount an old Store response after a Store-ID invalidation', async ({ page }) => {
  const nextStoreId = 'ef'.repeat(32);
  const nextProfile = '55'.repeat(32);
  const nextTopology = structuredClone(topology);
  nextTopology.receipt.projection_commit = { store_id: nextStoreId, sequence: '1' };
  nextTopology.data.sessions = ['capture-00000000000000000000000000000009'];
  nextTopology.data.sensors = [{ id: 'sensor-z', hardware_kind: 'esp32-s3', device_id: '9' }];
  nextTopology.data.links = [{
    id: 'link-z', space: 'room', transmitter: 'tx-z', receiver: 'sensor-z', profiles: [nextProfile],
  }];
  let activeTopology = topology;
  let activeStore = storeId;
  let delayOld = false;
  let signalStarted;
  let releaseSignal;
  const oldSignalStarted = new Promise((resolve) => { signalStarted = resolve; });
  const oldSignalRelease = new Promise((resolve) => { releaseSignal = resolve; });
  let socket;
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(activeTopology),
  }));
  await page.route('**/api/signals?**', async (route) => {
    const response = signalsFor(route.request().url(), activeStore, activeStore === storeId ? '5' : '1');
    if (delayOld && activeStore === storeId) {
      signalStarted();
      await oldSignalRelease;
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.routeWebSocket('**/api/live', (websocket) => {
    socket = websocket;
    websocket.send(JSON.stringify(live));
  });
  await page.goto('/');
  await expect(page.getByTestId('tile-heading')).toContainText('sensor-a');

  delayOld = true;
  await page.getByLabel('Metric').selectOption('q');
  await oldSignalStarted;
  activeTopology = nextTopology;
  activeStore = nextStoreId;
  socket.send(JSON.stringify({
    ...live,
    delivery_sequence: '1',
    projection_commit: { store_id: nextStoreId, sequence: '1' },
  }));
  releaseSignal();

  await expect(page.locator('#store-id')).toHaveText(nextStoreId);
  await expect(page.getByTestId('tile-heading')).toContainText('sensor-z · link-z');
  await expect(page.getByTestId('tile-heading')).not.toContainText('sensor-a');
});

test('treats a watermark only as invalidation until a complete HTTP response arrives', async ({ page }) => {
  let sequence = '5';
  let delaySignals = false;
  let startDelayedRequest;
  let releaseDelayedRequest;
  const delayedRequestStarted = new Promise((resolve) => { startDelayedRequest = resolve; });
  const delayedResponse = new Promise((resolve) => { releaseDelayedRequest = resolve; });
  let socket;
  await page.route('**/api/topology', (route) => {
    const response = structuredClone(topology);
    response.receipt.projection_commit.sequence = sequence;
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.route('**/api/signals?**', async (route) => {
    if (delaySignals) {
      startDelayedRequest();
      await delayedResponse;
    }
    const response = signalsFor(route.request().url(), storeId, sequence);
    if (sequence === '6') response.data.tiles[0].cells[2].value = 9;
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
  });
  await page.routeWebSocket('**/api/live', (websocket) => {
    socket = websocket;
    websocket.send(JSON.stringify(live));
  });
  await page.goto('/');
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.getByText('7', { exact: true })).toBeVisible();

  sequence = '6';
  delaySignals = true;
  socket.send(JSON.stringify({
    ...live,
    delivery_sequence: '1',
    projection_commit: { store_id: storeId, sequence: '6' },
  }));
  await delayedRequestStarted;
  await expect(page.getByTestId('connection-state')).toHaveText('POLLING');
  await expect(page.getByText('Retained result · stale')).toBeVisible();
  await expect(page.getByText('7', { exact: true })).toBeVisible();
  await expect(page.getByText('9', { exact: true })).toHaveCount(0);

  releaseDelayedRequest();
  await expect(page.getByText('9', { exact: true })).toBeVisible();
  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.getByText('Retained result · stale')).toBeHidden();
});

test('mounts a schema-valid empty signals response without fabricating cells', async ({ page }) => {
  await page.route('**/api/topology', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(topology),
  }));
  await page.route('**/api/signals?**', (route) => {
    const populated = signalsFor(route.request().url());
    const empty = {
      http_schema_version: 1,
      kind: 'empty',
      resource: 'signals',
      receipt: populated.receipt,
    };
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(empty) });
  });
  await page.routeWebSocket('**/api/live', (socket) => socket.send(JSON.stringify(live)));
  await page.goto('/');

  await expect(page.getByTestId('connection-state')).toHaveText('LIVE');
  await expect(page.getByText('No committed signal cells match this read context.')).toBeVisible();
  await expect(page.getByTestId('tile-heading')).toHaveCount(0);
  await expect(page.getByLabel('Measured zero')).toHaveCount(0);
});
