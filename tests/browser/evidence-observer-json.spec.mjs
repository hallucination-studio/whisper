import { expect, test } from '@playwright/test';

import { parseStrictJson } from '../../scripts/strict-json.mjs';

test('observer JSON parser rejects duplicate properties including escaped equivalents', () => {
  expect(() => parseStrictJson('{"kind":"ok","kind":"empty"}'))
    .toThrow('duplicate JSON property: kind');
  expect(() => parseStrictJson('{"kind":"ok","k\\u0069nd":"empty"}'))
    .toThrow('duplicate JSON property: kind');
});

test('observer JSON parser preserves valid whitespace, property order, and number spellings', () => {
  expect(parseStrictJson(' { "second" : 1.0e0, "first" : true } \n')).toEqual({
    first: true,
    second: 1,
  });
});
