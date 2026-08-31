export const storeId = 'ab'.repeat(32);
export const profiles = ['11'.repeat(32), '22'.repeat(32), '33'.repeat(32)];
export const sessions = [
  'capture-00000000000000000000000000000001',
  'capture-00000000000000000000000000000002',
];
export const semanticSessions = [
  'session-00000000000000000000000000000001',
  'session-00000000000000000000000000000002',
];

export const topology = {
  http_schema_version: 1,
  kind: 'ok',
  resource: 'topology',
  data: {
    deployment: 'lab',
    sessions,
    spaces: [{ id: 'room' }],
    sensors: [
      { id: 'sensor-a', hardware_kind: 'esp32-s3', device_id: '1' },
      { id: 'sensor-b', hardware_kind: 'esp32-s3', device_id: '2' },
    ],
    links: [
      {
        id: 'link-a',
        space: 'room',
        transmitter: 'tx-a',
        receiver: 'sensor-a',
        profiles: [profiles[0]],
      },
      {
        id: 'link-b',
        space: 'room',
        transmitter: 'tx-b',
        receiver: 'sensor-b',
        profiles: [profiles[1], profiles[2]],
      },
    ],
  },
  receipt: { projection_commit: { store_id: storeId, sequence: '5' } },
};

export const live = {
  http_schema_version: 1,
  delivery_sequence: '0',
  projection_commit: { store_id: storeId, sequence: '5' },
  payload: { kind: 'projection_watermark' },
};

export const relationshipSubjects = {
  http_schema_version: 1,
  kind: 'ok',
  resource: 'relationship_subjects',
  data: {
    subjects: [
      { session_id: semanticSessions[0], link: 'link-a', profile: profiles[0] },
      { session_id: semanticSessions[1], link: 'link-b', profile: profiles[1] },
      { session_id: semanticSessions[1], link: 'link-b', profile: profiles[2] },
    ],
  },
  receipt: { projection_commit: { store_id: storeId, sequence: '5' } },
};

export function relationshipLatestFor(url, responseStoreId = storeId, sequence = '5') {
  const query = new URL(url).searchParams;
  return {
    http_schema_version: 1,
    kind: 'ok',
    resource: 'relationship_latest',
    data: {
      session_id: query.get('session'),
      link: query.get('link'),
      profile: query.get('profile'),
      knowledge: { kind: 'unknown', reason: 'baseline_learning' },
      result_time: '1000000000',
      creator_commit: { store_id: responseStoreId, sequence },
    },
    receipt: {
      projection_commit: { store_id: responseStoreId, sequence },
      session_id: query.get('session'),
      first_record_seq: '0',
      last_record_seq: '4',
      decoder_version: 'native-frame-v1',
      conditioning_version: 'amplitude-v1',
      algorithm_version: 'baseline-v1',
    },
  };
}

export function signalsFor(url, responseStoreId = storeId, sequence = '5') {
  const query = new URL(url).searchParams;
  const session = query.get('session');
  const sensor = query.get('sensor');
  const link = query.get('link');
  const profile = query.get('profile') ?? profiles[0];
  const metric = query.get('metric');
  const aggregated = metric === 'amplitude';
  const from = BigInt(query.get('from'));
  const to = BigInt(query.get('to'));
  const buckets = BigInt(query.get('max_time_buckets'));
  const width = (to - from + buckets - 1n) / buckets;
  const aggregateTimeAxis = [];
  for (let current = from; current < to; current += width) aggregateTimeAxis.push(String(current));
  const aggregateCells = aggregateTimeAxis.flatMap(() => [
    { kind: 'min_max_mean_rms_count', minimum: 0, maximum: 0, mean: 0, rms: 0, count: 1 },
    null,
    { kind: 'min_max_mean_rms_count', minimum: 4, maximum: 8, mean: 6, rms: 6.4, count: 2 },
    { kind: 'min_max_mean_rms_count', minimum: 2, maximum: 2, mean: 2, rms: 2, count: 1 },
  ]);
  const receipt = {
    projection_commit: { store_id: responseStoreId, sequence },
    session_id: session,
    first_record_seq: '0',
    last_record_seq: '1',
    decoder_version: 'native-frame-v1',
    conditioning_version: 'amplitude-v1',
    algorithm_version: 'native-coordinate-ingest-v1',
  };
  return {
    http_schema_version: 1,
    kind: 'ok',
    resource: 'signals',
    data: {
      metric,
      tiles: [
        {
          stream: {
            key: { sensor, link, profile },
            device_epoch: { device_id: sensor === 'sensor-b' ? '2' : '1', boot_generation: 1 },
          },
          profile,
          time_axis: aggregated ? aggregateTimeAxis : ['10'],
          path_axis: [{ kind: 'raw_path_ordinal', ordinal: 0 }],
          sample_axis: { kind: 'opaque_sample_ordinal', count: 4 },
          order: 'time_path_coordinate',
          cells: aggregated ? aggregateCells : [
            { kind: 'raw', value: 0 }, null, { kind: 'raw', value: 7 }, { kind: 'raw', value: -3 },
          ],
          aggregation: aggregated ? 'min_max_mean_rms_count' : 'raw',
          missing_spans: [],
          receipt,
        },
      ],
    },
    receipt,
  };
}
