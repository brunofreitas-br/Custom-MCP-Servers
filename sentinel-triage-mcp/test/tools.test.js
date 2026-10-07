import assert from 'node:assert/strict';
import { once } from 'node:events';
import { test } from 'node:test';
import express from 'express';
import { userTokenStore } from '../dist/apiClient.js';
import { getTool, listTools } from '../dist/toolRegistry.js';
import { registerAllTools } from '../dist/tools/index.js';

registerAllTools();

function mockGraph(t, result = {}, status = 200) {
  const requests = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(new URL(url).origin, 'https://graph.microsoft.com');
    requests.push({
      url: new URL(url),
      method: options.method,
      headers: options.headers,
      body: options.body === undefined ? undefined : JSON.parse(options.body),
    });
    return Response.json(result, { status });
  });
  return requests;
}

async function invoke(name, args, token = 'triage-test-token') {
  const tool = getTool(name);
  assert.ok(tool, `Missing tool ${name}`);
  return userTokenStore.run(token, () => tool.handler(args));
}

test('discovery preserves the seven existing tools and adds two updates', () => {
  assert.deepEqual(listTools().map((tool) => tool.name).sort(), [
    'FetchAdvancedHuntingTablesDetailedSchema',
    'FetchAdvancedHuntingTablesOverview',
    'GetAlertById',
    'GetIncidentById',
    'ListAlerts',
    'ListIncidents',
    'RunAdvancedHuntingQuery',
    'UpdateAlert',
    'UpdateIncident',
  ].sort());
  for (const name of ['UpdateIncident', 'UpdateAlert']) {
    const schema = getTool(name).inputSchema;
    assert.equal(schema.additionalProperties, false);
    assert.equal(schema.minProperties, 2);
  }
});

test('UpdateIncident sends a PATCH with every supported field and preserves explicit clears', async (t) => {
  const updated = { id: '29', status: 'resolved', customTags: [] };
  const requests = mockGraph(t, updated);
  const fields = {
    status: 'resolved',
    assignedTo: null,
    classification: 'truePositive',
    determination: 'malware',
    severity: 'high',
    displayName: 'Confirmed malware',
    description: '',
    summary: 'Endpoint remediated',
    resolvingComment: 'Investigation and containment completed',
    customTags: [],
  };

  assert.deepEqual(await invoke('UpdateIncident', { incidentId: 'id/with?#', ...fields }), updated);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'PATCH');
  assert.equal(requests[0].url.href, 'https://graph.microsoft.com/v1.0/security/incidents/id%2Fwith%3F%23');
  assert.equal(requests[0].headers.Authorization, 'Bearer triage-test-token');
  assert.deepEqual(requests[0].body, fields);
});

test('UpdateAlert sends only supported alert fields to alerts_v2', async (t) => {
  const updated = { id: 'alert-1', status: 'inProgress' };
  const requests = mockGraph(t, updated);
  const fields = {
    status: 'inProgress',
    assignedTo: 'analyst@example.com',
    classification: 'truePositive',
    determination: 'phishing',
    customDetails: { ticket: 'SOC-123', note: '' },
  };

  assert.deepEqual(await invoke('UpdateAlert', { alertId: 'alert/with?#', ...fields }), updated);
  assert.equal(requests[0].method, 'PATCH');
  assert.equal(requests[0].url.href, 'https://graph.microsoft.com/v1.0/security/alerts_v2/alert%2Fwith%3F%23');
  assert.deepEqual(requests[0].body, fields);
});

for (const [name, idField] of [['UpdateIncident', 'incidentId'], ['UpdateAlert', 'alertId']]) {
  test(`${name} can close without inventing a classification or other changes`, async (t) => {
    const requests = mockGraph(t, { id: '1', status: 'resolved' });
    await invoke(name, { [idField]: '1', status: 'resolved' });
    assert.deepEqual(requests[0].body, { status: 'resolved' });
  });
}

test('updates can reopen incidents and clear alert assignments', async (t) => {
  const requests = mockGraph(t);
  await invoke('UpdateIncident', { incidentId: '1', status: 'active' });
  await invoke('UpdateAlert', { alertId: '2', assignedTo: null, customDetails: {} });
  assert.deepEqual(requests.map((request) => request.body), [
    { status: 'active' },
    { assignedTo: null, customDetails: {} },
  ]);
});

const invalidUpdates = [
  ['missing ID', 'UpdateIncident', { status: 'resolved' }, /incidentId/],
  ['empty ID', 'UpdateAlert', { alertId: ' ', status: 'resolved' }, /alertId/],
  ['numeric ID', 'UpdateIncident', { incidentId: 29, status: 'resolved' }, /incidentId/],
  ['empty patch', 'UpdateIncident', { incidentId: '29' }, /at least one field/],
  ['null arguments', 'UpdateAlert', null, /arguments must be an object/],
  ['array arguments', 'UpdateIncident', [], /arguments must be an object/],
  ['misspelled field', 'UpdateIncident', { incidentId: '1', stauts: 'resolved' }, /Unsupported update field/],
  ['alert-only status on incident', 'UpdateIncident', { incidentId: '1', status: 'inProgress' }, /status must be one of/],
  ['incident-only status on alert', 'UpdateAlert', { alertId: '1', status: 'active' }, /status must be one of/],
  ['null status', 'UpdateAlert', { alertId: '1', status: null }, /status must be/],
  ['unknown classification', 'UpdateIncident', { incidentId: '1', classification: 'benign' }, /classification must be one of/],
  ['empty determination', 'UpdateAlert', { alertId: '1', determination: '' }, /determination must be/],
  ['invalid severity', 'UpdateIncident', { incidentId: '1', severity: 'critical' }, /severity must be one of/],
  ['unsupported alert severity', 'UpdateAlert', { alertId: '1', severity: 'high' }, /Unsupported update field/],
  ['blank assignment', 'UpdateIncident', { incidentId: '1', assignedTo: ' ' }, /assignedTo must be/],
  ['invalid assignment type', 'UpdateAlert', { alertId: '1', assignedTo: false }, /assignedTo must be/],
  ['blank display name', 'UpdateIncident', { incidentId: '1', displayName: '' }, /displayName must be/],
  ['invalid tags type', 'UpdateIncident', { incidentId: '1', customTags: 'tag' }, /customTags must be/],
  ['empty tag', 'UpdateIncident', { incidentId: '1', customTags: [''] }, /customTags must be/],
  ['non-string tag', 'UpdateIncident', { incidentId: '1', customTags: [123] }, /customTags must be/],
  ['non-string custom detail', 'UpdateAlert', { alertId: '1', customDetails: { ticket: 123 } }, /customDetails must be/],
  ['array custom details', 'UpdateAlert', { alertId: '1', customDetails: [] }, /customDetails must be/],
  ['null custom details', 'UpdateAlert', { alertId: '1', customDetails: null }, /customDetails must be/],
  ['inherited property name', 'UpdateIncident', { incidentId: '1', toString: 'x' }, /Unsupported update field/],
];

for (const [label, name, args, message] of invalidUpdates) {
  test(`rejects ${label} before making an API call`, async (t) => {
    const requests = mockGraph(t);
    await assert.rejects(invoke(name, args), message);
    assert.equal(requests.length, 0);
  });
}

test('missing user tokens fail without an API call', async (t) => {
  const requests = mockGraph(t);
  await assert.rejects(invoke('UpdateIncident', { incidentId: '1', status: 'resolved' }, ''), /No user token/);
  assert.equal(requests.length, 0);
});

for (const status of [403, 429]) {
  test(`propagates Graph HTTP ${status} without a success-shaped response`, async (t) => {
    const requests = mockGraph(t, { error: { message: 'Upstream rejected the update' } }, status);
    await assert.rejects(invoke('UpdateAlert', { alertId: '1', status: 'resolved' }), new RegExp(`HTTP ${status}`));
    assert.equal(requests.length, 1);
  });
}

test('concurrent updates keep user tokens isolated across async boundaries', async (t) => {
  const requests = mockGraph(t);
  await Promise.all(['user-a', 'user-b'].map((token) =>
    userTokenStore.run(token, async () => {
      await new Promise((resolve) => setImmediate(resolve));
      return getTool('UpdateIncident').handler({ incidentId: token, status: 'resolved' });
    }),
  ));
  for (const request of requests) {
    const id = request.url.pathname.split('/').at(-1);
    assert.equal(request.headers.Authorization, `Bearer ${id}`);
  }
  assert.equal(requests.length, 2);
});

test('existing incident filtering and hunting payloads remain unchanged', async (t) => {
  const result = { value: [], '@odata.nextLink': 'https://graph.microsoft.com/next-page' };
  const requests = mockGraph(t, result);
  assert.deepEqual(await invoke('ListIncidents', {
    severity: 'high', status: 'active', includeAlertsData: true, top: 10, skip: 0,
  }), result);
  assert.equal(requests[0].method, 'GET');
  assert.equal(requests[0].url.searchParams.get('$filter'), "severity eq 'high' and status eq 'active'");
  assert.equal(requests[0].url.searchParams.get('$expand'), 'alerts');
  assert.equal(requests[0].url.searchParams.get('$top'), '10');
  assert.equal(requests[0].url.searchParams.get('$skip'), '0');
  await invoke('RunAdvancedHuntingQuery', { kqlQuery: 'DeviceEvents | take 1', timespan: 'P1D' });
  assert.equal(requests[1].method, 'POST');
  assert.deepEqual(requests[1].body, { Query: 'DeviceEvents | take 1', Timespan: 'P1D' });
});

test('HTTP MCP exposes and executes both update tools with standard success and error envelopes', async (t) => {
  const clientFetch = globalThis.fetch;
  const updated = { id: '1', status: 'resolved' };
  const requests = mockGraph(t, updated);
  const listen = express.application.listen;
  let server;
  t.mock.method(express.application, 'listen', function (_port, callback) {
    server = listen.call(this, 0, '127.0.0.1', callback);
    return server;
  });
  await import('../dist/server.js');
  assert.ok(server);
  t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  if (!server.listening) await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}`;

  async function rpc(method, params, authenticated = true) {
    const response = await clientFetch(`${base}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(authenticated ? { Authorization: 'Bearer protocol-test-token' } : {}),
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    assert.equal(response.status, 200);
    return response.json();
  }

  const health = await (await clientFetch(`${base}/health`)).json();
  assert.equal(health.tools, 9);
  assert.equal((await rpc('initialize')).result.protocolVersion, '2024-11-05');
  assert.equal((await rpc('tools/list')).result.tools.length, 9);
  for (const [name, idField] of [['UpdateIncident', 'incidentId'], ['UpdateAlert', 'alertId']]) {
    const response = await rpc('tools/call', { name, arguments: { [idField]: '1', status: 'resolved' } });
    assert.equal(response.jsonrpc, '2.0');
    assert.equal(response.id, 1);
    assert.deepEqual(JSON.parse(response.result.content[0].text), updated);
    assert.equal(response.result.isError, undefined);
  }
  const invalid = await rpc('tools/call', { name: 'UpdateAlert', arguments: { alertId: '1', status: 'active' } });
  assert.equal(invalid.result.isError, true);
  const unauthenticated = await rpc('tools/call', {
    name: 'UpdateIncident', arguments: { incidentId: '1', status: 'resolved' },
  }, false);
  assert.equal(unauthenticated.result.isError, true);
  assert.equal(requests.length, 2);
  assert.ok(requests.every((request) => request.headers.Authorization === 'Bearer protocol-test-token'));
});
