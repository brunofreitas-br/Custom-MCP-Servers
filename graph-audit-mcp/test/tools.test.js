import assert from 'node:assert/strict';
import { test } from 'node:test';
import { userTokenStore, validateContinuationUrl } from '../dist/apiClient.js';
import { getTool, listTools } from '../dist/toolRegistry.js';
import '../dist/tools.js';

const TOKEN = 'unit-test-token';

function invoke(name, args, token = TOKEN) {
  const tool = getTool(name);
  assert.ok(tool, `Expected registered tool ${name}`);
  return userTokenStore.run(token, () => tool.handler(args));
}

function mockGraph(t, responses) {
  const requests = [];
  t.mock.method(globalThis, 'fetch', async (input, options) => {
    const url = new URL(input);
    requests.push({ url, options });
    const response = responses[requests.length - 1];
    assert.ok(response, `Unexpected request ${url}`);
    return Response.json(response.body ?? {}, { status: response.status ?? 200, headers: response.headers });
  });
  return requests;
}

test('discovery exposes exactly six strict schemas', () => {
  const tools = listTools();
  assert.deepEqual(tools.map((tool) => tool.name), [
    'ListSignIns',
    'GetSignInById',
    'ListDirectoryAudits',
    'GetDirectoryAuditById',
    'ListRiskyUsers',
    'GetRiskyUserById',
  ]);
  for (const tool of tools) {
    assert.equal(tool.inputSchema.type, 'object');
    assert.equal(tool.inputSchema.additionalProperties, false);
  }
});

test('ListSignIns constructs encoded allowlisted filters and forwards only the request token', async (t) => {
  const requests = mockGraph(t, [{ body: { value: [{ id: 'one' }] } }]);
  const result = await invoke('ListSignIns', {
    userId: "user'o",
    ipAddress: '192.0.2.10',
    statusErrorCode: 0,
    startDateTime: '2026-10-01T00:00:00Z',
    endDateTime: '2026-10-30T23:59:59Z',
    pageSize: 25,
  });
  assert.deepEqual(result, { value: [{ id: 'one' }], pagesFetched: 1 });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url.pathname, '/v1.0/auditLogs/signIns');
  assert.equal(requests[0].url.searchParams.get('$top'), '25');
  assert.equal(
    requests[0].url.searchParams.get('$filter'),
    "userId eq 'user''o' and ipAddress eq '192.0.2.10' and status/errorCode eq 0 and createdDateTime ge 2026-10-01T00:00:00Z and createdDateTime le 2026-10-30T23:59:59Z",
  );
  assert.equal(requests[0].options.headers.Authorization, `Bearer ${TOKEN}`);
});

test('get tools encode IDs as one path segment', async (t) => {
  const requests = mockGraph(t, [{ body: { id: 'id with spaces' } }]);
  await invoke('GetSignInById', { id: 'id with spaces' });
  assert.equal(requests[0].url.pathname, '/v1.0/auditLogs/signIns/id%20with%20spaces');
});

test('validation rejects unknown fields, invalid values and unsafe IDs before Graph calls', async (t) => {
  const fetchMock = t.mock.method(globalThis, 'fetch', () => {
    assert.fail('Graph must not be called for invalid arguments');
  });
  await assert.rejects(invoke('ListSignIns', { select: '*' }), /Unsupported argument: select/);
  await assert.rejects(invoke('ListSignIns', { pageSize: 1001 }), /between 1 and 1000/);
  await assert.rejects(invoke('ListSignIns', { maxPages: 6 }), /between 1 and 5/);
  await assert.rejects(invoke('ListSignIns', { startDateTime: 'not-a-date' }), /ISO 8601/);
  await assert.rejects(invoke('ListSignIns', { startDateTime: '2026-02-30T00:00:00Z' }), /valid timestamp/);
  await assert.rejects(invoke('ListRiskyUsers', { riskState: 'compromisedMaybe' }), /riskState must be one of/);
  await assert.rejects(invoke('GetRiskyUserById', { id: '../users' }), /valid Microsoft Graph resource ID/);
  assert.equal(fetchMock.mock.callCount(), 0);
});

test('bounded pagination aggregates pages and preserves the remaining nextLink', async (t) => {
  const next2 = 'https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$skiptoken=second';
  const next3 = 'https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$skiptoken=third';
  const requests = mockGraph(t, [
    { body: { value: [{ id: '1' }], '@odata.nextLink': next2 } },
    { body: { value: [{ id: '2' }], '@odata.nextLink': next3 } },
  ]);
  const result = await invoke('ListRiskyUsers', { maxPages: 2 });
  assert.deepEqual(result, {
    value: [{ id: '1' }, { id: '2' }],
    '@odata.nextLink': next3,
    pagesFetched: 2,
  });
  assert.equal(requests.length, 2);
  assert.equal(requests[1].url.searchParams.get('$skiptoken'), 'second');
});

test('continuation validation only accepts HTTPS Graph v1.0 exact collection paths', () => {
  const valid = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=safe';
  assert.equal(validateContinuationUrl(valid, '/auditLogs/directoryAudits').toString(), valid);
  for (const unsafe of [
    'http://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=x',
    'https://evil.example/v1.0/auditLogs/directoryAudits?$skiptoken=x',
    'https://graph.microsoft.com/beta/auditLogs/directoryAudits?$skiptoken=x',
    'https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=x',
    'https://user:pass@graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=x',
  ]) {
    assert.throws(() => validateContinuationUrl(unsafe, '/auditLogs/directoryAudits'), /unexpected continuation URL/);
  }
});

test('parallel requests keep passthrough tokens isolated', async (t) => {
  const seen = [];
  t.mock.method(globalThis, 'fetch', async (_input, options) => {
    seen.push(options.headers.Authorization);
    await new Promise((resolve) => setTimeout(resolve, options.headers.Authorization.endsWith('first') ? 15 : 1));
    return Response.json({ value: [] });
  });
  await Promise.all([
    invoke('ListSignIns', {}, 'first'),
    invoke('ListSignIns', {}, 'second'),
  ]);
  assert.deepEqual(new Set(seen), new Set(['Bearer first', 'Bearer second']));
});

test('missing authentication fails without a request', async (t) => {
  const fetchMock = t.mock.method(globalThis, 'fetch', () => assert.fail('fetch must not run'));
  await assert.rejects(
    userTokenStore.run(undefined, () => getTool('ListSignIns').handler({})),
    /Missing authentication/,
  );
  assert.equal(fetchMock.mock.callCount(), 0);
});

test('malformed successful collection responses are failures, not empty results', async (t) => {
  mockGraph(t, [{ body: { unexpected: [] } }]);
  await assert.rejects(invoke('ListDirectoryAudits', {}), /invalid collection response/);
});
