(() => {
  'use strict';

  const U64_MAX = 18446744073709551615n;
  const POLL_INTERVAL_MS = 250;
  const RECONNECT_INTERVAL_MS = 500;
  const METRICS = new Set(['i', 'q', 'amplitude', 'phase']);
  const RELATIONSHIP_UNKNOWN_REASONS = new Set([
    'baseline_missing', 'baseline_learning', 'insufficient_coverage', 'low_quality',
    'ambiguous_evidence', 'time_uncertain', 'missing_data', 'profile_mismatch',
    'stale', 'frozen', 'inactive', 'non_finite',
  ]);
  const HEX64 = /^[0-9a-f]{64}$/;
  const U64 = /^(0|[1-9][0-9]*)$/;
  const IDENTIFIER_CONTENT = /[^\p{White_Space}]/u;
  const utf8 = new TextEncoder();
  const utf8Decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const dom = {
    connection: document.querySelector('[data-testid="connection-state"]'),
    detail: document.querySelector('#connection-detail'),
    deployment: document.querySelector('#deployment-id'),
    store: document.querySelector('#store-id'),
    watermark: document.querySelector('#watermark'),
    stale: document.querySelector('#stale-indicator'),
    message: document.querySelector('#message'),
    view: document.querySelector('#signal-view'),
    session: document.querySelector('#session-select'),
    sensor: document.querySelector('#sensor-select'),
    link: document.querySelector('#link-select'),
    profile: document.querySelector('#profile-select'),
    metric: document.querySelector('#metric-select'),
    from: document.querySelector('#from-input'),
    to: document.querySelector('#to-input'),
    path: document.querySelector('#path-select'),
    modeControls: [...document.querySelectorAll('input[name="view-mode"]')],
    contextLabel: document.querySelector('#context-label'),
    contextHeading: document.querySelector('#context-heading'),
    contextCopy: document.querySelector('#context-copy'),
    captureControls: document.querySelector('#capture-controls'),
    sensingControls: document.querySelector('#sensing-controls'),
    signalPanel: document.querySelector('#signal-panel'),
    relationshipPanel: document.querySelector('#relationship-panel'),
    relationshipMessage: document.querySelector('#relationship-message'),
    relationshipView: document.querySelector('#relationship-view'),
    relationshipSession: document.querySelector('#relationship-session-select'),
    relationshipLink: document.querySelector('#relationship-link-select'),
    relationshipProfile: document.querySelector('#relationship-profile-select'),
    relationshipState: document.querySelector('#relationship-state'),
    relationshipResultTime: document.querySelector('#relationship-result-time'),
    relationshipChange: document.querySelector('#relationship-change'),
    relationshipChangeState: document.querySelector('#relationship-change-state'),
    relationshipChangeTime: document.querySelector('#relationship-change-time'),
  };
  const maxTimeBuckets = document.documentElement.dataset.maxTimeBuckets;
  const state = {
    topology: null,
    signals: null,
    relationshipSubjects: null,
    relationshipLatest: null,
    viewMode: 'signal',
    storeId: null,
    pendingWatermark: null,
    latestWatermark: null,
    pollTimer: null,
    reconnectTimer: null,
    websocket: null,
    websocketReady: false,
    polling: false,
    refreshRequested: false,
    readToken: null,
    stale: false,
    protocolError: false,
  };

  class HttpFailure extends Error {}
  class ProtocolFailure extends Error {}

  class JsonNumber {
    constructor(lexeme, value) { this.lexeme = lexeme; this.value = value; }
    valueOf() { return this.value; }
    toString() { return String(this.value); }
    toJSON() { return this.value; }
  }

  class StrictJsonParser {
    constructor(text) { this.text = text; this.position = 0; }
    parse() {
      const value = this.value();
      this.space();
      if (this.position !== this.text.length) throw new Error('trailing JSON input');
      return value;
    }
    space() {
      while ([' ', '\t', '\n', '\r'].includes(this.text[this.position])) this.position += 1;
    }
    value() {
      this.space();
      const token = this.text[this.position];
      if (token === '{') return this.object();
      if (token === '[') return this.array();
      if (token === '"') return this.string();
      if (token === 't') return this.literal('true', true);
      if (token === 'f') return this.literal('false', false);
      if (token === 'n') return this.literal('null', null);
      return this.number();
    }
    object() {
      const result = Object.create(null);
      const keys = new Set();
      this.position += 1;
      this.space();
      if (this.text[this.position] === '}') { this.position += 1; return result; }
      while (true) {
        this.space();
        if (this.text[this.position] !== '"') throw new Error('object key is not a string');
        const key = this.string();
        if (keys.has(key)) throw new Error(`duplicate JSON property: ${key}`);
        keys.add(key);
        this.space();
        if (this.text[this.position] !== ':') throw new Error('missing object colon');
        this.position += 1;
        result[key] = this.value();
        this.space();
        const delimiter = this.text[this.position++];
        if (delimiter === '}') return result;
        if (delimiter !== ',') throw new Error('invalid object delimiter');
      }
    }
    array() {
      const result = [];
      this.position += 1;
      this.space();
      if (this.text[this.position] === ']') { this.position += 1; return result; }
      while (true) {
        result.push(this.value());
        this.space();
        const delimiter = this.text[this.position++];
        if (delimiter === ']') return result;
        if (delimiter !== ',') throw new Error('invalid array delimiter');
      }
    }
    string() {
      const start = this.position;
      this.position += 1;
      let escaped = false;
      while (this.position < this.text.length) {
        const character = this.text[this.position++];
        if (!escaped && character === '"') {
          return JSON.parse(this.text.slice(start, this.position));
        }
        if (!escaped && character === '\\') escaped = true;
        else escaped = false;
      }
      throw new Error('unterminated JSON string');
    }
    literal(token, value) {
      if (this.text.slice(this.position, this.position + token.length) !== token) {
        throw new Error('invalid JSON literal');
      }
      this.position += token.length;
      return value;
    }
    number() {
      const match = this.text.slice(this.position).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
      if (!match) throw new Error('invalid JSON value');
      this.position += match[0].length;
      const value = Number(match[0]);
      if (!Number.isFinite(value) || Object.is(value, -0)) throw new Error('invalid finite number');
      return new JsonNumber(match[0], value);
    }
  }

  function parseStrict(text) { return new StrictJsonParser(text).parse(); }
  function object(value) {
    return value !== null && typeof value === 'object'
      && !Array.isArray(value) && !(value instanceof JsonNumber);
  }
  function exact(value, required, optional = []) {
    if (!object(value)) return false;
    const allowed = new Set([...required, ...optional]);
    return required.every((key) => Object.hasOwn(value, key))
      && Object.keys(value).every((key) => allowed.has(key));
  }
  function textId(value) {
    return typeof value === 'string' && scalarString(value) && IDENTIFIER_CONTENT.test(value)
      && utf8.encode(value).length <= 4294967295;
  }
  function scalarString(value) {
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
  function hex64(value) { return typeof value === 'string' && HEX64.test(value); }
  function u64(value, nonzero = false) {
    if (typeof value !== 'string' || !U64.test(value)) return false;
    const parsed = BigInt(value);
    return parsed <= U64_MAX && (!nonzero || parsed > 0n);
  }
  function exactInteger(value) {
    if (!(value instanceof JsonNumber)) return null;
    const match = value.lexeme.match(/^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/);
    if (!match) return null;
    const fraction = match[3] ?? '';
    const digits = match[2] + fraction;
    if (!/[1-9]/.test(digits)) return 0n;
    const decimalPlace = BigInt(match[2].length) + BigInt(match[4] ?? '0');
    if (decimalPlace <= 0n) return null;
    let integerDigits;
    if (decimalPlace < BigInt(digits.length)) {
      const split = Number(decimalPlace);
      if (/[1-9]/.test(digits.slice(split))) return null;
      integerDigits = digits.slice(0, split);
    } else {
      if (decimalPlace > 20n) return null;
      integerDigits = digits + '0'.repeat(Number(decimalPlace - BigInt(digits.length)));
    }
    const integer = BigInt(integerDigits);
    return match[1] ? -integer : integer;
  }
  function smallInteger(value, minimum, maximum) {
    const integer = exactInteger(value);
    return integer !== null && integer >= BigInt(minimum) && integer <= BigInt(maximum);
  }
  function finite(value) {
    return value instanceof JsonNumber && Number.isFinite(value.value) && !Object.is(value.value, -0);
  }
  function unique(values) { return new Set(values).size === values.length; }
  function compareBytes(left, right) {
    const a = utf8.encode(left);
    const b = utf8.encode(right);
    const length = Math.min(a.length, b.length);
    for (let index = 0; index < length; index += 1) {
      if (a[index] !== b[index]) return a[index] - b[index];
    }
    return a.length - b.length;
  }
  function strictlyOrdered(values, select = (value) => value, compare = compareBytes) {
    for (let index = 1; index < values.length; index += 1) {
      if (compare(select(values[index - 1]), select(values[index])) >= 0) return false;
    }
    return true;
  }
  function watermark(value, committed = false) {
    return exact(value, ['store_id', 'sequence']) && hex64(value.store_id) && u64(value.sequence, committed);
  }
  function storeReceipt(value) { return exact(value, ['projection_commit']) && watermark(value.projection_commit); }
  function viewReceipt(value) {
    if (!(exact(value, [
      'projection_commit', 'session_id', 'first_record_seq', 'last_record_seq',
      'decoder_version', 'conditioning_version', 'algorithm_version',
    ]) && watermark(value.projection_commit, true) && textId(value.session_id)
      && u64(value.first_record_seq) && u64(value.last_record_seq)
      && textId(value.decoder_version) && textId(value.conditioning_version)
      && textId(value.algorithm_version))) return false;
    return BigInt(value.first_record_seq) <= BigInt(value.last_record_seq);
  }
  function path(value) {
    if (!object(value)) return false;
    if (value.kind === 'raw_path_ordinal') {
      return exact(value, ['kind', 'ordinal']) && smallInteger(value.ordinal, 0, 65535);
    }
    return value.kind === 'tx_rx' && exact(value, ['kind', 'tx_stream', 'rx_chain'])
      && smallInteger(value.tx_stream, 0, 65535) && smallInteger(value.rx_chain, 0, 65535);
  }
  function comparePath(left, right) {
    const leftKind = left.kind === 'tx_rx' ? 0 : 1;
    const rightKind = right.kind === 'tx_rx' ? 0 : 1;
    if (leftKind !== rightKind) return leftKind - rightKind;
    if (left.kind === 'raw_path_ordinal') return left.ordinal - right.ordinal;
    return left.tx_stream - right.tx_stream || left.rx_chain - right.rx_chain;
  }
  function sampleAxis(value) {
    if (!object(value)) return false;
    if (value.kind === 'opaque_sample_ordinal') {
      return exact(value, ['kind', 'count']) && smallInteger(value.count, 1, 65535);
    }
    if (value.kind === 'ieee_tone_index') {
      return exact(value, ['kind', 'values']) && Array.isArray(value.values) && value.values.length > 0
        && value.values.every((item) => smallInteger(item, -32768, 32767))
        && strictlyOrdered(value.values, (item) => item, (left, right) => left - right);
    }
    return value.kind === 'frequency_hz' && exact(value, ['kind', 'values'])
      && Array.isArray(value.values) && value.values.length > 0 && value.values.every((item) => u64(item))
      && strictlyOrdered(value.values, (item) => item, (left, right) => {
        const a = BigInt(left); const b = BigInt(right); return a < b ? -1 : (a > b ? 1 : 0);
      });
  }
  function sampleCount(axis) { return axis.kind === 'opaque_sample_ordinal' ? axis.count : axis.values.length; }
  function bucket(value) {
    if (value === null) return true;
    if (!object(value)) return false;
    if (value.kind === 'raw') return exact(value, ['kind', 'value']) && finite(value.value);
    return value.kind === 'min_max_mean_rms_count'
      && exact(value, ['kind', 'minimum', 'maximum', 'mean', 'rms', 'count'])
      && finite(value.minimum) && finite(value.maximum) && finite(value.mean) && finite(value.rms)
      && value.minimum <= value.mean && value.mean <= value.maximum && value.rms >= 0
      && smallInteger(value.count, 1, 4294967295);
  }
  function stream(value) {
    return exact(value, ['key', 'device_epoch'])
      && exact(value.key, ['sensor', 'link', 'profile'])
      && textId(value.key.sensor) && textId(value.key.link) && hex64(value.key.profile)
      && exact(value.device_epoch, ['device_id', 'boot_generation'])
      && u64(value.device_epoch.device_id)
      && smallInteger(value.device_epoch.boot_generation, 1, 4294967295);
  }
  function tile(value, metric) {
    if (!exact(value, [
      'stream', 'profile', 'time_axis', 'path_axis', 'sample_axis', 'order', 'cells',
      'aggregation', 'missing_spans', 'receipt',
    ])) return false;
    if (!stream(value.stream) || !hex64(value.profile) || value.profile !== value.stream.key.profile) return false;
    if (!Array.isArray(value.time_axis) || value.time_axis.length === 0
      || !value.time_axis.every((item) => u64(item))
      || value.time_axis.some((item, index) => index > 0 && BigInt(item) < BigInt(value.time_axis[index - 1]))) return false;
    if (!Array.isArray(value.path_axis) || value.path_axis.length === 0 || !value.path_axis.every(path)
      || !strictlyOrdered(value.path_axis, (item) => item, comparePath)) return false;
    if (!sampleAxis(value.sample_axis) || value.order !== 'time_path_coordinate') return false;
    if (!['raw', 'min_max_mean_rms_count'].includes(value.aggregation)) return false;
    const length = value.time_axis.length * value.path_axis.length * sampleCount(value.sample_axis);
    const expectedBucket = value.aggregation === 'raw' ? 'raw' : 'min_max_mean_rms_count';
    if (value.aggregation !== 'raw' && metric === 'phase') return false;
    return Array.isArray(value.cells) && value.cells.length === length && value.cells.every(bucket)
      && value.cells.every((cell) => cell === null || cell.kind === expectedBucket)
      && Array.isArray(value.missing_spans) && value.missing_spans.length === 0 && viewReceipt(value.receipt);
  }
  function topologyBody(value) {
    if (!exact(value, ['http_schema_version', 'kind', 'resource', 'data', 'receipt'])
      || !smallInteger(value.http_schema_version, 1, 1) || value.kind !== 'ok' || value.resource !== 'topology'
      || !storeReceipt(value.receipt)) return false;
    const data = value.data;
    if (!exact(data, ['deployment', 'sessions', 'spaces', 'sensors', 'links']) || !textId(data.deployment)) return false;
    if (!Array.isArray(data.sessions) || !data.sessions.every(textId) || !strictlyOrdered(data.sessions)) return false;
    if (!Array.isArray(data.spaces) || !data.spaces.every((item) => exact(item, ['id']) && textId(item.id))) return false;
    if (!Array.isArray(data.sensors) || !data.sensors.every((item) =>
      exact(item, ['id', 'hardware_kind', 'device_id']) && textId(item.id)
      && item.hardware_kind === 'esp32-s3' && u64(item.device_id))) return false;
    if (!Array.isArray(data.links) || !data.links.every((item) =>
      exact(item, ['id', 'space', 'transmitter', 'receiver', 'profiles'])
      && textId(item.id) && textId(item.space) && textId(item.transmitter) && textId(item.receiver)
      && Array.isArray(item.profiles) && item.profiles.every(hex64) && unique(item.profiles))) return false;
    const spaceIds = data.spaces.map((item) => item.id);
    const sensorIds = data.sensors.map((item) => item.id);
    const linkIds = data.links.map((item) => item.id);
    if (!strictlyOrdered(spaceIds) || !strictlyOrdered(sensorIds) || !strictlyOrdered(linkIds)
      || data.links.some((item) => !strictlyOrdered(item.profiles))
      || data.links.some((item) => !spaceIds.includes(item.space) || !sensorIds.includes(item.receiver))) return false;
    if (value.receipt.projection_commit.sequence === '0') {
      return data.sessions.length === 0 && data.links.every((item) => item.profiles.length === 0);
    }
    return true;
  }
  function compareTileKey(left, right) {
    for (let index = 0; index < 3; index += 1) {
      const comparison = compareBytes(left[index], right[index]);
      if (comparison !== 0) return comparison;
    }
    const a = BigInt(left[3]); const b = BigInt(right[3]);
    if (a !== b) return a < b ? -1 : 1;
    return left[4] - right[4];
  }
  function signalsBody(value) {
    return exact(value, ['http_schema_version', 'kind', 'resource', 'data', 'receipt'])
      && smallInteger(value.http_schema_version, 1, 1) && value.kind === 'ok' && value.resource === 'signals'
      && exact(value.data, ['metric', 'tiles']) && METRICS.has(value.data.metric)
      && Array.isArray(value.data.tiles) && value.data.tiles.length > 0
      && value.data.tiles.every((item) => tile(item, value.data.metric))
      && value.data.tiles.every((item) => item.aggregation === value.data.tiles[0].aggregation)
      && strictlyOrdered(value.data.tiles, (item) => [
        item.stream.key.sensor, item.stream.key.link, item.profile,
        item.stream.device_epoch.device_id, item.stream.device_epoch.boot_generation,
      ], compareTileKey)
      && viewReceipt(value.receipt)
      && value.data.tiles.every((item) => receiptsEqual(item.receipt, value.receipt));
  }
  function emptySignalsBody(value) {
    return exact(value, ['http_schema_version', 'kind', 'resource', 'receipt'])
      && smallInteger(value.http_schema_version, 1, 1) && value.kind === 'empty' && value.resource === 'signals'
      && viewReceipt(value.receipt);
  }
  function signalsResponse(value) { return signalsBody(value) || emptySignalsBody(value); }
  function compareRelationshipSubject(left, right) {
    return compareBytes(left.session_id, right.session_id)
      || compareBytes(left.link, right.link)
      || compareBytes(left.profile, right.profile);
  }
  function relationshipSubjectsBody(value) {
    return exact(value, ['http_schema_version', 'kind', 'resource', 'data', 'receipt'])
      && smallInteger(value.http_schema_version, 1, 1) && value.kind === 'ok'
      && value.resource === 'relationship_subjects'
      && exact(value.data, ['subjects']) && Array.isArray(value.data.subjects)
      && value.data.subjects.every((subject) => exact(subject, ['session_id', 'link', 'profile'])
        && textId(subject.session_id) && textId(subject.link) && hex64(subject.profile))
      && strictlyOrdered(value.data.subjects, (subject) => subject, compareRelationshipSubject)
      && storeReceipt(value.receipt)
      && (value.receipt.projection_commit.sequence !== '0' || value.data.subjects.length === 0);
  }
  function relationshipKnowledge(value) {
    if (!object(value)) return false;
    if (value.kind === 'known') {
      return exact(value, ['kind', 'value'])
        && (value.value === 'stable' || value.value === 'changing');
    }
    return value.kind === 'unknown' && exact(value, ['kind', 'reason'])
      && RELATIONSHIP_UNKNOWN_REASONS.has(value.reason);
  }
  function relationshipChange(value) {
    return exact(value, ['previous', 'current', 'changed_at'])
      && relationshipKnowledge(value.previous) && relationshipKnowledge(value.current)
      && u64(value.changed_at);
  }
  function relationshipLatestBody(value) {
    if (!exact(value, ['http_schema_version', 'kind', 'resource', 'receipt'], ['data'])
      || !smallInteger(value.http_schema_version, 1, 1)
      || value.resource !== 'relationship_latest' || !viewReceipt(value.receipt)) return false;
    if (value.kind === 'empty') return !Object.hasOwn(value, 'data');
    if (value.kind !== 'ok' || !exact(value.data, [
      'session_id', 'link', 'profile', 'knowledge', 'result_time', 'creator_commit',
    ], ['most_recent_change'])) return false;
    const data = value.data;
    return textId(data.session_id) && textId(data.link) && hex64(data.profile)
      && relationshipKnowledge(data.knowledge) && u64(data.result_time)
      && watermark(data.creator_commit, true)
      && data.creator_commit.store_id === value.receipt.projection_commit.store_id
      && BigInt(data.creator_commit.sequence) <= BigInt(value.receipt.projection_commit.sequence)
      && (!Object.hasOwn(data, 'most_recent_change') || relationshipChange(data.most_recent_change));
  }
  function errorEnvelope(value, status, allowedCodes) {
    if (!exact(value, ['http_schema_version', 'kind', 'error'])
      || !smallInteger(value.http_schema_version, 1, 1) || value.kind !== 'error' || !object(value.error)) return false;
    const error = value.error;
    if (typeof error.message !== 'string' || !scalarString(error.message) || error.message.length === 0) return false;
    const expectedStatus = {
      invalid_request: 400,
      range_unavailable: 416,
      phase_over_budget: 422,
      projection_failed: 500,
    }[error.code];
    if (status !== expectedStatus || !allowedCodes.has(error.code)) return false;
    if (['invalid_request', 'projection_failed'].includes(error.code)) {
      return exact(error, ['code', 'message']);
    }
    if (error.code === 'range_unavailable') {
      return exact(error, ['code', 'message'])
        || (exact(error, ['code', 'message', 'available_from', 'available_to'])
          && u64(error.available_from) && u64(error.available_to)
          && BigInt(error.available_from) <= BigInt(error.available_to));
    }
    return error.code === 'phase_over_budget'
      && exact(error, ['code', 'message', 'max_signal_points']) && u64(error.max_signal_points, true);
  }
  function liveBody(value) {
    return exact(value, ['http_schema_version', 'delivery_sequence', 'projection_commit', 'payload'])
      && smallInteger(value.http_schema_version, 1, 1) && u64(value.delivery_sequence)
      && watermark(value.projection_commit)
      && exact(value.payload, ['kind']) && value.payload.kind === 'projection_watermark';
  }
  function receiptsEqual(left, right) {
    return left.session_id === right.session_id
      && left.first_record_seq === right.first_record_seq
      && left.last_record_seq === right.last_record_seq
      && left.decoder_version === right.decoder_version
      && left.conditioning_version === right.conditioning_version
      && left.algorithm_version === right.algorithm_version
      && left.projection_commit.store_id === right.projection_commit.store_id
      && left.projection_commit.sequence === right.projection_commit.sequence;
  }

  async function read(url, validator, allowedErrors) {
    const response = await fetch(url, { headers: { accept: 'application/json' }, cache: 'no-store' });
    const contentType = response.headers.get('content-type') ?? '';
    if (!/^application\/json(?:;|$)/i.test(contentType)) {
      throw new ProtocolFailure(`${url} has an invalid Content-Type`);
    }
    let text;
    try { text = utf8Decoder.decode(await response.arrayBuffer()); }
    catch { throw new ProtocolFailure(`${url} is not exact UTF-8`); }
    let value;
    try { value = parseStrict(text); } catch (error) { throw new ProtocolFailure(error.message); }
    if (!response.ok) {
      if (!errorEnvelope(value, response.status, allowedErrors)) {
        throw new ProtocolFailure(`${url} returned an invalid error body`);
      }
      throw new HttpFailure(`${url} returned ${response.status}`);
    }
    if (response.status !== 200) throw new ProtocolFailure(`${url} returned a noncanonical success status`);
    let valid = false;
    try { valid = validator(value); } catch { throw new ProtocolFailure(`invalid ${url} response`); }
    if (!valid) throw new ProtocolFailure(`invalid ${url} response`);
    return value;
  }
  function option(label, value) { const item = document.createElement('option'); item.textContent = label; item.value = value; return item; }
  function syncSelect(select, entries, preferred) {
    const next = entries.some((entry) => entry.value === preferred) ? preferred : (entries[0]?.value ?? '');
    select.replaceChildren(...entries.map((entry) => option(entry.label, entry.value)));
    select.value = next;
    select.disabled = entries.length === 0;
    return next;
  }
  function currentSelection() {
    return {
      session: dom.session.value,
      sensor: dom.sensor.value,
      link: dom.link.value,
      profile: dom.profile.value,
    };
  }
  function sameSelection(left, right) {
    return ['session', 'sensor', 'link', 'profile'].every((key) => left[key] === right[key]);
  }
  function preferredValue(entries, preferred) {
    return entries.some((entry) => entry.value === preferred) ? preferred : (entries[0]?.value ?? '');
  }
  function proposeSelections(topology, preferred) {
    const sessionEntries = topology.data.sessions.map((value) => ({ label: value, value }));
    const sensorEntries = topology.data.sensors.map((value) => ({ label: value.id, value: value.id }));
    const session = preferredValue(sessionEntries, preferred.session);
    const sensor = preferredValue(sensorEntries, preferred.sensor);
    const links = topology.data.links.filter((value) => value.receiver === sensor);
    const linkEntries = links.map((value) => ({ label: value.id, value: value.id }));
    const link = preferredValue(linkEntries, preferred.link);
    const selectedLink = links.find((value) => value.id === link);
    const profileEntries = (selectedLink?.profiles ?? []).map((value) => ({ label: value, value }));
    const profile = preferredValue(profileEntries, preferred.profile);
    return {
      sessionEntries, sensorEntries, linkEntries, profileEntries,
      session, sensor, link, profile,
    };
  }
  function applySelections(selection, resetPath) {
    syncSelect(dom.session, selection.sessionEntries, selection.session);
    syncSelect(dom.sensor, selection.sensorEntries, selection.sensor);
    syncSelect(dom.link, selection.linkEntries, selection.link);
    syncSelect(dom.profile, selection.profileEntries, selection.profile);
    if (resetPath) syncSelect(dom.path, [{ label: 'All applicable paths', value: '' }], '');
  }
  function currentRelationshipSelection() {
    return {
      session: dom.relationshipSession.value,
      link: dom.relationshipLink.value,
      profile: dom.relationshipProfile.value,
    };
  }
  function proposeRelationshipSelections(subjects, preferred) {
    const sessionEntries = [...new Set(subjects.data.subjects.map((subject) => subject.session_id))]
      .map((value) => ({ label: value, value }));
    const session = preferredValue(sessionEntries, preferred.session);
    const sessionSubjects = subjects.data.subjects.filter((subject) => subject.session_id === session);
    const linkEntries = [...new Set(sessionSubjects.map((subject) => subject.link))]
      .map((value) => ({ label: value, value }));
    const link = preferredValue(linkEntries, preferred.link);
    const profileEntries = sessionSubjects.filter((subject) => subject.link === link)
      .map((subject) => ({ label: subject.profile, value: subject.profile }));
    const profile = preferredValue(profileEntries, preferred.profile);
    return { sessionEntries, linkEntries, profileEntries, session, link, profile };
  }
  function applyRelationshipSelections(selection) {
    syncSelect(dom.relationshipSession, selection.sessionEntries, selection.session);
    syncSelect(dom.relationshipLink, selection.linkEntries, selection.link);
    syncSelect(dom.relationshipProfile, selection.profileEntries, selection.profile);
  }
  function relationshipSelectionComplete(selection) {
    return selection.session && selection.link && selection.profile;
  }
  function relationshipRequest(selection) {
    const query = new URLSearchParams({
      session: selection.session,
      link: selection.link,
      profile: selection.profile,
    });
    return { ...selection, url: `/api/relationships/latest?${query}` };
  }
  function relationshipMatchesRequest(latest, request) {
    if (latest.receipt.session_id !== request.session) return false;
    if (latest.kind === 'empty') return true;
    return latest.data.session_id === request.session
      && latest.data.link === request.link
      && latest.data.profile === request.profile;
  }
  function unmountSignals(message) {
    state.signals = null;
    dom.view.replaceChildren();
    dom.message.hidden = false;
    dom.message.textContent = message;
    setStale(false);
  }
  function selectionComplete(selection) {
    return selection.session && selection.sensor && selection.link && selection.profile;
  }
  function canonicalInput(input) { return u64(input.value) ? input.value : null; }
  function pathValue(selectedPath) {
    if (!selectedPath) return '';
    return selectedPath.kind === 'raw_path_ordinal'
      ? `raw_path_ordinal:${selectedPath.ordinal}` : `tx_rx:${selectedPath.tx_stream}:${selectedPath.rx_chain}`;
  }
  function signalRequest(selection, retainPath) {
    const from = canonicalInput(dom.from);
    const to = canonicalInput(dom.to);
    if (!from || !to || BigInt(from) > BigInt(to) || !u64(maxTimeBuckets)
      || BigInt(maxTimeBuckets) > 4294967295n) throw new Error('invalid interval');
    const context = {
      session: selection.session,
      sensor: selection.sensor,
      link: selection.link,
      profile: selection.profile,
      metric: dom.metric.value,
      from,
      to,
      maxTimeBuckets,
      selectedPath: retainPath && dom.path.value ? JSON.parse(dom.path.value) : null,
    };
    const query = new URLSearchParams({
      session: context.session, sensor: context.sensor, link: context.link,
      from, to, metric: context.metric, max_time_buckets: maxTimeBuckets,
      profile: context.profile,
    });
    const encodedPath = pathValue(context.selectedPath);
    if (encodedPath) query.set('path', encodedPath);
    return { ...context, url: `/api/signals?${query}` };
  }
  function aggregateAxis(context) {
    const from = BigInt(context.from);
    const to = BigInt(context.to);
    const buckets = BigInt(context.maxTimeBuckets);
    const duration = to - from;
    const width = (duration + buckets - 1n) / buckets;
    const axis = [];
    for (let current = from; current < to; current += width) axis.push(String(current));
    return axis;
  }
  function signalsMatchRequest(signals, context) {
    if (signals.receipt.session_id !== context.session) return false;
    if (signals.kind === 'empty') return true;
    if (signals.data.metric !== context.metric) return false;
    return signals.data.tiles.every((item) => {
      if (item.stream.key.sensor !== context.sensor || item.stream.key.link !== context.link
        || item.profile !== context.profile) return false;
      if (context.selectedPath
        && (item.path_axis.length !== 1 || comparePath(item.path_axis[0], context.selectedPath) !== 0)) return false;
      if (item.aggregation === 'raw') {
        const from = BigInt(context.from); const to = BigInt(context.to);
        return item.time_axis.every((time) => BigInt(time) >= from && BigInt(time) < to);
      }
      const expected = aggregateAxis(context);
      return item.time_axis.length === expected.length
        && item.time_axis.every((time, index) => time === expected[index]);
    });
  }
  function setMode(mode, detail) {
    dom.connection.textContent = mode;
    dom.connection.dataset.mode = {
      LIVE: 'live',
      POLLING: 'polling',
      'PROTOCOL ERROR': 'protocol-error',
    }[mode];
    dom.detail.textContent = detail;
  }
  function setStale(stale) { state.stale = stale; dom.stale.hidden = !stale; }
  function hasRetainedResult() {
    return state.viewMode === 'signal' ? state.signals !== null : state.relationshipLatest !== null;
  }
  function ensurePolling() {
    if (state.pollTimer === null) state.pollTimer = window.setInterval(refresh, POLL_INTERVAL_MS);
  }
  function stopPolling() {
    if (state.pollTimer !== null) window.clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  function discardContext(nextStore) {
    state.readToken = null;
    state.refreshRequested = true;
    state.storeId = nextStore;
    state.topology = null;
    state.signals = null;
    state.relationshipSubjects = null;
    state.relationshipLatest = null;
    state.pendingWatermark = null;
    state.latestWatermark = null;
    dom.deployment.textContent = 'Not read';
    dom.store.textContent = 'Not read';
    dom.store.removeAttribute('title');
    dom.watermark.textContent = '—';
    setStale(false);
    dom.view.replaceChildren();
    dom.message.hidden = false;
    dom.message.textContent = 'Store identity changed. Reading a complete context…';
    dom.session.replaceChildren(); dom.sensor.replaceChildren(); dom.link.replaceChildren(); dom.profile.replaceChildren();
    dom.relationshipSession.replaceChildren();
    dom.relationshipLink.replaceChildren();
    dom.relationshipProfile.replaceChildren();
    dom.relationshipView.hidden = true;
    dom.relationshipMessage.hidden = false;
    dom.relationshipMessage.textContent = 'Store identity changed. Reading a complete context…';
    syncSelect(dom.path, [{ label: 'All applicable paths', value: '' }], '');
  }
  function pathLabel(value) {
    if (value.kind === 'raw_path_ordinal') return `Raw path ordinal ${value.ordinal}`;
    return `Transmit stream ${value.tx_stream} · receive chain ${value.rx_chain}`;
  }
  function sampleLabels(axis) {
    if (axis.kind === 'opaque_sample_ordinal') return Array.from({ length: axis.count }, (_, index) => `Opaque sample ordinal ${index}`);
    if (axis.kind === 'ieee_tone_index') return axis.values.map((value) => `IEEE tone index ${value}`);
    return axis.values.map((value) => `Frequency ${value} Hz`);
  }
  function formatNumber(value) {
    const number = value.value;
    return Number.isInteger(number) ? String(number) : number.toPrecision(6).replace(/0+$/, '').replace(/\.$/, '');
  }
  function renderCell(cell) {
    const element = document.createElement('td');
    if (cell === null) {
      element.className = 'cell-missing'; element.setAttribute('aria-label', 'Missing value'); element.textContent = '∅ missing'; return element;
    }
    if (cell.kind === 'raw') {
      if (cell.value.value === 0) {
        element.className = 'cell-zero'; element.setAttribute('aria-label', 'Measured zero');
        const zero = document.createElement('span'); zero.textContent = '0'; element.append(zero);
      } else element.textContent = formatNumber(cell.value);
      return element;
    }
    element.className = 'aggregate';
    for (const [label, value] of [['min', cell.minimum], ['max', cell.maximum], ['mean', cell.mean], ['rms', cell.rms], ['count', cell.count]]) {
      const key = document.createElement('b'); key.textContent = label;
      const content = document.createElement('span'); content.textContent = formatNumber(value);
      element.append(key, content);
    }
    return element;
  }
  function renderTile(tile) {
    const section = document.createElement('article'); section.className = 'tile';
    const header = document.createElement('header'); header.className = 'tile-header';
    const heading = document.createElement('h3'); heading.dataset.testid = 'tile-heading';
    heading.textContent = `${tile.stream.key.sensor} · ${tile.stream.key.link}`;
    const meta = document.createElement('div'); meta.className = 'tile-meta';
    meta.textContent = `Profile ${tile.profile} · device ${tile.stream.device_epoch.device_id} / boot ${tile.stream.device_epoch.boot_generation}`;
    header.append(heading, meta);
    const scroll = document.createElement('div'); scroll.className = 'grid-scroll';
    const table = document.createElement('table'); table.className = 'signal-grid';
    const labels = sampleLabels(tile.sample_axis);
    const head = document.createElement('tr');
    for (const label of ['Session time (ns)', 'Path', ...labels]) { const th = document.createElement('th'); th.scope = 'col'; th.textContent = label; head.append(th); }
    const thead = document.createElement('thead'); thead.append(head); table.append(thead);
    const body = document.createElement('tbody');
    const samples = labels.length;
    tile.time_axis.forEach((time, timeIndex) => tile.path_axis.forEach((nativePath, pathIndex) => {
      const row = document.createElement('tr');
      const timeCell = document.createElement('th'); timeCell.scope = 'row'; timeCell.textContent = time;
      const pathCell = document.createElement('th'); pathCell.scope = 'row'; pathCell.textContent = pathLabel(nativePath);
      row.append(timeCell, pathCell);
      const offset = (timeIndex * tile.path_axis.length + pathIndex) * samples;
      for (let sample = 0; sample < samples; sample += 1) row.append(renderCell(tile.cells[offset + sample]));
      body.append(row);
    }));
    table.append(body); scroll.append(table); section.append(header, scroll); return section;
  }
  function syncPaths(signals) {
    const values = new Map();
    for (const currentTile of signals.data.tiles) {
      for (const currentPath of currentTile.path_axis) values.set(JSON.stringify(currentPath), pathLabel(currentPath));
    }
    const entries = [{ label: 'All applicable paths', value: '' }, ...[...values].map(([value, label]) => ({ value, label }))];
    syncSelect(dom.path, entries, dom.path.value);
  }
  function titleCaseToken(value) {
    return value.split('_').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('');
  }
  function knowledgeLabel(knowledge) {
    if (knowledge.kind === 'unknown') return `Unknown(${titleCaseToken(knowledge.reason)})`;
    return titleCaseToken(knowledge.value);
  }
  function mountRelationship(topology, subjects, latest) {
    state.topology = topology;
    state.relationshipSubjects = subjects;
    state.relationshipLatest = latest;
    dom.deployment.textContent = topology.data.deployment;
    dom.store.textContent = topology.receipt.projection_commit.store_id;
    dom.store.title = topology.receipt.projection_commit.store_id;
    dom.watermark.textContent = topology.receipt.projection_commit.sequence;
    if (latest.kind === 'ok') {
      dom.relationshipState.textContent = knowledgeLabel(latest.data.knowledge);
      dom.relationshipResultTime.textContent = `${latest.data.result_time} ns`;
      const change = latest.data.most_recent_change;
      dom.relationshipChange.hidden = change === undefined;
      if (change !== undefined) {
        dom.relationshipChangeState.textContent = `${knowledgeLabel(change.previous)} → ${knowledgeLabel(change.current)}`;
        dom.relationshipChangeTime.textContent = `${change.changed_at} ns`;
      }
      dom.relationshipMessage.hidden = true;
      dom.relationshipView.hidden = false;
    } else {
      dom.relationshipView.hidden = true;
      dom.relationshipMessage.hidden = false;
      dom.relationshipMessage.textContent = 'No committed relationship window is available for this subject.';
    }
    setStale(false);
  }
  function mount(topology, signals) {
    state.topology = topology; state.signals = signals;
    dom.deployment.textContent = topology.data.deployment;
    dom.store.textContent = topology.receipt.projection_commit.store_id;
    dom.store.title = topology.receipt.projection_commit.store_id;
    dom.watermark.textContent = topology.receipt.projection_commit.sequence;
    if (signals.kind === 'ok') {
      syncPaths(signals);
      dom.view.replaceChildren(...signals.data.tiles.map(renderTile));
      dom.message.hidden = true;
    } else {
      syncSelect(dom.path, [{ label: 'All applicable paths', value: '' }], '');
      dom.view.replaceChildren();
      dom.message.hidden = false;
      dom.message.textContent = 'No committed signal cells match this read context.';
    }
    setStale(false);
  }
  function qualifies(resources, target) {
    if (!state.websocketReady || !target || resources.some((resource) => !resource)) return false;
    return resources.every((resource) => {
      const commit = resource.receipt.projection_commit;
      return commit.store_id === target.store_id
        && BigInt(commit.sequence) >= BigInt(target.sequence);
    });
  }
  async function refresh() {
    if (state.polling) { state.refreshRequested = true; return; }
    state.polling = true;
    state.refreshRequested = false;
    const token = Symbol('Store read');
    state.readToken = token;
    try {
      const topology = await read('/api/topology', topologyBody, new Set(['projection_failed']));
      if (state.readToken !== token) return;
      const incomingStore = topology.receipt.projection_commit.store_id;
      if (state.storeId !== null && state.storeId !== incomingStore) {
        discardContext(incomingStore);
        state.readToken = token;
      }
      state.storeId = incomingStore;
      if (state.viewMode === 'signal') {
        const previousSelection = currentSelection();
        const proposedSelection = proposeSelections(topology, previousSelection);
        const selectionChanged = !sameSelection(previousSelection, proposedSelection);
        if (!selectionComplete(proposedSelection)) {
          applySelections(proposedSelection, true);
          state.topology = topology;
          state.signals = null;
          dom.deployment.textContent = topology.data.deployment;
          dom.store.textContent = incomingStore;
          dom.watermark.textContent = topology.receipt.projection_commit.sequence;
          dom.message.hidden = false;
          dom.message.textContent = 'No committed Capture Session and Profile are available.';
          dom.view.replaceChildren();
          syncSelect(dom.path, [{ label: 'All applicable paths', value: '' }], '');
          setStale(false);
          state.protocolError = false;
          setMode('POLLING', 'Complete topology read · waiting for a selectable signals context');
          ensurePolling();
          return;
        }
        const request = signalRequest(proposedSelection, !selectionChanged);
        const signals = await read(
          request.url,
          signalsResponse,
          new Set(['invalid_request', 'range_unavailable', 'phase_over_budget', 'projection_failed']),
        );
        if (state.readToken !== token) return;
        if (signals.receipt.projection_commit.store_id !== incomingStore) throw new ProtocolFailure('Store IDs do not match');
        if (!signalsMatchRequest(signals, request)) throw new ProtocolFailure('signals selection does not match');
        applySelections(proposedSelection, selectionChanged);
        mount(topology, signals);
        state.protocolError = false;
        setMode('POLLING', 'Complete HTTP resources read · waiting for WebSocket synchronization');
        ensurePolling();
        if (qualifies([topology, signals], state.pendingWatermark)) {
          state.latestWatermark = state.pendingWatermark;
          state.protocolError = false;
          setMode('LIVE', 'WebSocket invalidation synchronized with complete Store reads');
          stopPolling();
        }
      } else {
        const subjects = await read(
          '/api/relationships/latest',
          relationshipSubjectsBody,
          new Set(['projection_failed']),
        );
        if (state.readToken !== token) return;
        if (subjects.receipt.projection_commit.store_id !== incomingStore) {
          throw new ProtocolFailure('Store IDs do not match');
        }
        const previousSelection = currentRelationshipSelection();
        const proposedSelection = proposeRelationshipSelections(subjects, previousSelection);
        const selectionChanged = ['session', 'link', 'profile']
          .some((key) => previousSelection[key] !== proposedSelection[key]);
        applyRelationshipSelections(proposedSelection);
        if (!relationshipSelectionComplete(proposedSelection)) {
          state.topology = topology;
          state.relationshipSubjects = subjects;
          state.relationshipLatest = null;
          dom.deployment.textContent = topology.data.deployment;
          dom.store.textContent = incomingStore;
          dom.watermark.textContent = topology.receipt.projection_commit.sequence;
          dom.relationshipView.hidden = true;
          dom.relationshipMessage.hidden = false;
          dom.relationshipMessage.textContent = 'No committed relationship subjects are available.';
          setStale(false);
          state.protocolError = false;
          setMode('POLLING', 'Complete subject read · waiting for a selectable relationship');
          ensurePolling();
          return;
        }
        const request = relationshipRequest(proposedSelection);
        const latest = await read(
          request.url,
          relationshipLatestBody,
          new Set(['invalid_request', 'range_unavailable', 'projection_failed']),
        );
        if (state.readToken !== token) return;
        if (latest.receipt.projection_commit.store_id !== incomingStore) {
          throw new ProtocolFailure('Store IDs do not match');
        }
        if (!relationshipMatchesRequest(latest, request)) {
          throw new ProtocolFailure('relationship selection does not match');
        }
        if (selectionChanged) dom.relationshipView.hidden = true;
        mountRelationship(topology, subjects, latest);
        state.protocolError = false;
        setMode('POLLING', 'Complete relationship read · waiting for WebSocket synchronization');
        ensurePolling();
        if (qualifies([topology, subjects, latest], state.pendingWatermark)) {
          state.latestWatermark = state.pendingWatermark;
          state.protocolError = false;
          setMode('LIVE', 'WebSocket invalidation synchronized with complete Store reads');
          stopPolling();
        }
      }
    } catch (error) {
      setStale(hasRetainedResult());
      if (error instanceof ProtocolFailure) {
        state.protocolError = true;
        setMode('PROTOCOL ERROR', 'A response failed canonical validation');
      } else {
        setMode('POLLING', state.signals ? 'Poll failed · retaining the last complete result' : 'Waiting for a complete Store read');
      }
      ensurePolling();
    } finally {
      state.polling = false;
      if (state.refreshRequested) queueMicrotask(refresh);
    }
  }
  function connect() {
    if (state.websocket && state.websocket.readyState < WebSocket.CLOSING) return;
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(`${protocol}//${location.host}/api/live`);
    let deliverySequence = null;
    state.websocketReady = false;
    state.websocket = socket;
    socket.addEventListener('message', (event) => {
      try {
        const message = parseStrict(event.data);
        if (!liveBody(message)) throw new Error('invalid WebSocket message');
        const nextDelivery = BigInt(message.delivery_sequence);
        if (deliverySequence === null && nextDelivery !== 0n) {
          throw new Error('WebSocket handshake delivery sequence is not zero');
        }
        if (deliverySequence !== null && nextDelivery <= deliverySequence) {
          throw new Error('non-increasing WebSocket delivery sequence');
        }
        deliverySequence = nextDelivery;
        if (state.pendingWatermark
          && state.pendingWatermark.store_id === message.projection_commit.store_id
          && BigInt(message.projection_commit.sequence) < BigInt(state.pendingWatermark.sequence)) {
          throw new Error('regressing projection watermark');
        }
        if (state.storeId !== null && state.storeId !== message.projection_commit.store_id) {
          discardContext(message.projection_commit.store_id);
        }
        state.pendingWatermark = message.projection_commit;
        state.websocketReady = true;
        state.protocolError = false;
        state.readToken = null;
        state.refreshRequested = true;
        setStale(hasRetainedResult());
        setMode('POLLING', 'Watermark received · reading complete HTTP resources');
        ensurePolling();
        refresh();
      } catch {
        state.websocketReady = false;
        state.protocolError = true;
        setMode('PROTOCOL ERROR', 'A WebSocket message failed canonical validation');
        socket.close();
      }
    });
    socket.addEventListener('close', () => {
      state.websocketReady = false;
      if (!state.protocolError) setMode('POLLING', 'WebSocket closed · fixed 250 ms HTTP polling');
      setStale(hasRetainedResult());
      ensurePolling();
      if (state.reconnectTimer === null) {
        state.reconnectTimer = window.setTimeout(() => { state.reconnectTimer = null; connect(); }, RECONNECT_INTERVAL_MS);
      }
    });
    socket.addEventListener('error', () => socket.close());
  }
  function selectionChanged() {
    state.readToken = null;
    state.refreshRequested = true;
    unmountSignals('Selection changed. Reading a complete signals resource…');
    setMode('POLLING', 'Selection changed · reading a complete signals resource');
    ensurePolling();
    refresh();
  }
  function relationshipSelectionChanged() {
    state.readToken = null;
    state.refreshRequested = true;
    state.relationshipLatest = null;
    dom.relationshipView.hidden = true;
    dom.relationshipMessage.hidden = false;
    dom.relationshipMessage.textContent = 'Selection changed. Reading a complete relationship resource…';
    setStale(false);
    setMode('POLLING', 'Selection changed · reading a complete relationship resource');
    ensurePolling();
    refresh();
  }
  function viewModeChanged(event) {
    state.viewMode = event.target.value;
    const sensing = state.viewMode === 'sensing';
    dom.captureControls.hidden = sensing;
    dom.sensingControls.hidden = !sensing;
    dom.signalPanel.hidden = sensing;
    dom.relationshipPanel.hidden = !sensing;
    dom.contextLabel.textContent = sensing ? 'Sensing context' : 'Capture context';
    dom.contextHeading.textContent = sensing ? 'Read the RF relationship' : 'Follow the committed path';
    dom.contextCopy.textContent = sensing
      ? 'Select one committed Semantic Session, Link, and Profile.'
      : 'Select Store-backed identities. These controls only change the read view.';
    state.readToken = null;
    state.refreshRequested = true;
    setStale(false);
    if (sensing) {
      state.relationshipLatest = null;
      dom.relationshipView.hidden = true;
      dom.relationshipMessage.hidden = false;
      dom.relationshipMessage.textContent = 'Reading relationship subjects…';
    } else {
      unmountSignals('Reading topology…');
    }
    setMode('POLLING', 'View changed · reading complete Store resources');
    ensurePolling();
    refresh();
  }
  dom.session.addEventListener('change', selectionChanged);
  dom.sensor.addEventListener('change', () => { dom.link.value = ''; dom.profile.value = ''; selectionChanged(); });
  dom.link.addEventListener('change', () => { dom.profile.value = ''; selectionChanged(); });
  for (const control of [dom.profile, dom.metric, dom.from, dom.to, dom.path]) control.addEventListener('change', selectionChanged);
  dom.relationshipSession.addEventListener('change', () => {
    dom.relationshipLink.value = '';
    dom.relationshipProfile.value = '';
    relationshipSelectionChanged();
  });
  dom.relationshipLink.addEventListener('change', () => {
    dom.relationshipProfile.value = '';
    relationshipSelectionChanged();
  });
  dom.relationshipProfile.addEventListener('change', relationshipSelectionChanged);
  for (const control of dom.modeControls) control.addEventListener('change', viewModeChanged);
  setMode('POLLING', 'Waiting for complete Store reads');
  ensurePolling();
  connect();
  refresh();
})();
