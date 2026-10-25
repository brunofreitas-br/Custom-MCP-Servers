import assert from 'node:assert/strict';
import { once } from 'node:events';
import { test } from 'node:test';
import express from 'express';
import { userTokenStore } from '../dist/apiClient.js';
import { getTool } from '../dist/toolRegistry.js';
import { toolErrorDetails } from '../dist/toolErrors.js';
import { registerAllTools } from '../dist/tools/index.js';

process.env.CASE_MANAGEMENT_ENABLED = 'true';
registerAllTools();
const namespace = 'microsoft.graph.security.caseManagement';
const lookupPath = `/beta/security/caseManagement/cases/${namespace}.incidentCase`;
const token = 'local-triage-diagnostic-token';

function mockGraph(t, steps) {
  const requests = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    const step = steps[requests.length];
    const request = { url: new URL(url), method: options.method, headers: options.headers, body: options.body ? JSON.parse(options.body) : undefined };
    requests.push(request);
    assert.ok(step, `Unexpected request: ${url}`);
    assert.equal(request.url.origin, 'https://graph.microsoft.com');
    assert.equal(request.url.pathname, step.path);
    assert.equal(request.method, step.method ?? 'GET');
    assert.equal(request.headers.Authorization, `Bearer ${token}`);
    step.check?.(request);
    if (step.error) throw step.error;
    const status = step.status ?? 200;
    if (status === 202) return new Response(null, { status });
    if (step.raw !== undefined) return new Response(step.raw, { status, headers: step.headers });
    return Response.json(step.body ?? {}, { status, headers: step.headers });
  });
  t.after(() => assert.equal(requests.length, steps.length));
  return requests;
}

function invoke(name, args) {
  return userTokenStore.run(token, () => getTool(name).handler(args));
}

test('a Cases 403 retains scope-neutral guidance and cannot cause another API request', async (t) => {
  mockGraph(t, [{
    path: '/beta/security/caseManagement/cases/30', status: 403,
    body: { error: { code: 'AccessDenied', message: 'You do not have permission to edit this case.' } },
    headers: { 'request-id': 'cases-request', 'client-request-id': 'echoed-client-id' },
  }]);
  await assert.rejects(invoke('GetCaseById', { caseId: '30' }), (error) => {
    const data = toolErrorDetails(error, 'GetCaseById', { caseId: '30' });
    assert.equal(data.diagnostics.httpStatus, 403);
    assert.equal(data.diagnostics.upstream.errorCode, 'AccessDenied');
    assert.equal(data.diagnostics.upstream.requestId, 'cases-request');
    assert.equal(data.diagnostics.upstream.clientRequestId, 'echoed-client-id');
    assert.equal(data.diagnostics.upstream.method, 'GET');
    assert.deepEqual(data.diagnostics.target, { caseId: '30' });
    assert.equal(data.diagnostics.automaticRetryAllowed, false);
    assert.match(data.diagnostics.guidance.join(' '), /does not prove which permission/);
    return true;
  });
});

test('both failed paths retain their own HTTP context, request IDs and distinct references', async (t) => {
  mockGraph(t, [
    { path: lookupPath, status: 404, body: { error: { code: 'NotFound' } }, headers: { 'request-id': 'cases-404' } },
    { path: '/v1.0/security/incidents/912805', status: 404, body: { error: { code: 'ResourceNotFound', message: 'Incident was not found' } }, headers: { 'request-id': 'incident-404' } },
  ]);
  await assert.rejects(invoke('GetIncidentById', { incidentId: '912805' }), (error) => {
    const data = toolErrorDetails(error, 'GetIncidentById', { incidentId: '912805' });
    assert.equal(data.diagnostics.routingReason, 'http-404');
    assert.equal(data.diagnostics.attempts.length, 2);
    assert.equal(data.diagnostics.attempts[0].upstream.requestId, 'cases-404');
    assert.equal(data.diagnostics.attempts[1].upstream.requestId, 'incident-404');
    assert.deepEqual(data.diagnostics.target, { incidentId: '912805' });
    assert.equal(data.diagnostics.target.caseId, undefined);
    return true;
  });
});

test('legacy-only tag writes preserve the full body and disclose the compatibility route on failure', async (t) => {
  mockGraph(t, [{
    path: '/v1.0/security/incidents/912805', method: 'PATCH', status: 404,
    body: { error: { code: 'ResourceNotFound' } },
    check: (request) => assert.deepEqual(request.body, { customTags: ['JIRA N2'], summary: 'Escalated' }),
  }]);
  const args = { incidentId: '912805', customTags: ['JIRA N2'], summary: 'Escalated' };
  await assert.rejects(invoke('UpdateIncident', args), (error) => {
    const data = toolErrorDetails(error, 'UpdateIncident', args);
    assert.equal(data.diagnostics.routingReason, 'legacy-compatibility');
    assert.equal(data.diagnostics.upstream.method, 'PATCH');
    assert.equal(data.diagnostics.httpStatus, 404);
    assert.equal(data.diagnostics.automaticRetryAllowed, false);
    return true;
  });
});

test('innerError correlation identifiers are retained without requiring header copies', async (t) => {
  mockGraph(t, [{
    path: '/beta/security/caseManagement/cases/missing', status: 404,
    body: { error: { code: 'ResourceNotFound', innerError: { 'request-id': 'inner-request', date: '2026-10-25T20:00:00Z' } } },
  }]);
  await assert.rejects(invoke('GetCaseById', { caseId: 'missing' }), (error) => {
    const data = toolErrorDetails(error, 'GetCaseById', { caseId: 'missing' });
    assert.equal(data.diagnostics.upstream.requestId, 'inner-request');
    assert.equal(data.diagnostics.upstream.date, '2026-10-25T20:00:00Z');
    assert.match(data.diagnostics.upstream.clientRequestId, /^[a-f0-9-]{36}$/);
    return true;
  });
});

test('upstream responses cannot echo the forwarded access token in diagnostics', async (t) => {
  mockGraph(t, [{ path: lookupPath, status: 403, body: { error: { message: `Rejected ${token}` } } }]);
  await assert.rejects(invoke('GetIncidentById', { incidentId: '912805' }), (error) => {
    assert.equal(JSON.stringify(toolErrorDetails(error, 'GetIncidentById', { incidentId: '912805' })).includes(token), false);
    return true;
  });
});

test('throttling retains Retry-After and does not turn into a legacy lookup', async (t) => {
  mockGraph(t, [{ path: lookupPath, status: 429, headers: { 'retry-after': '45' } }]);
  await assert.rejects(invoke('GetIncidentById', { incidentId: '912805' }), (error) => {
    assert.equal(toolErrorDetails(error, 'GetIncidentById', {}).diagnostics.upstream.retryAfter, '45');
    return true;
  });
});

for (const [label, step, code] of [
  ['network failure', { error: new TypeError('unavailable') }, 'UPSTREAM_NETWORK_ERROR'],
  ['HTML instead of JSON', { raw: '<html>not Graph JSON</html>' }, 'INVALID_UPSTREAM_RESPONSE'],
]) {
  test(`${label} is explicit and cannot trigger fallback`, async (t) => {
    mockGraph(t, [{ path: lookupPath, ...step }]);
    await assert.rejects(invoke('GetIncidentById', { incidentId: '912805' }), (error) => {
      assert.equal(toolErrorDetails(error, 'GetIncidentById', {}).diagnostics.code, code);
      return true;
    });
  });
}

test('HTTP MCP returns structured failures and partial results while separating route 404 from Graph 404', async (t) => {
  const clientFetch = globalThis.fetch;
  const resource = { '@odata.type': `#${namespace}.incidentCase`, id: '16296', incidentId: 912805, status: 'Active' };
  mockGraph(t, [
    { path: '/beta/security/caseManagement/cases/30', status: 403, headers: { 'request-id': 'http-403' } },
    { path: lookupPath, body: { value: [resource] } },
    { path: '/v1.0/security/incidents/912805', status: 404, headers: { 'request-id': 'enrichment-404' } },
  ]);
  const listen = express.application.listen;
  let server;
  t.mock.method(express.application, 'listen', function (_port, callback) {
    server = listen.call(this, 0, '127.0.0.1', callback);
    return server;
  });
  await import('../dist/server.js');
  t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  if (!server.listening) await once(server, 'listening');
  const address = server.address();
  const url = `http://127.0.0.1:${address.port}`;
  async function rpc(name, args) {
    return (await clientFetch(`${url}/mcp`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
    })).json();
  }
  const failure = await rpc('GetCaseById', { caseId: '30' });
  assert.equal(failure.result.isError, true);
  const details = JSON.parse(failure.result.content[0].text);
  assert.equal(details.diagnostics.upstream.requestId, 'http-403');
  assert.equal(details.diagnostics.target.caseId, '30');
  const partial = await rpc('GetIncidentById', { incidentId: '912805', includeAlertsData: true });
  assert.equal(partial.result.isError, true);
  const data = JSON.parse(partial.result.content[0].text);
  assert.equal(data.diagnostics.resourceFound, true);
  assert.equal(data.diagnostics.stage, 'alert-enrichment');
  assert.equal(data.diagnostics.upstream.requestId, 'enrichment-404');
  assert.equal(data.partialResult.caseId, '16296');
  assert.equal(data.partialResult.id, '912805');
  const wrongRoute = await clientFetch(`${url}/`, { method: 'POST' });
  assert.equal(wrongRoute.status, 404);
  assert.deepEqual((await wrongRoute.json()).expectedEndpoints, ['/mcp']);
});
