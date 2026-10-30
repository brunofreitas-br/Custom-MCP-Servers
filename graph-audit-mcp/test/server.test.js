import assert from 'node:assert/strict';
import { once } from 'node:events';
import { test } from 'node:test';
import { createApp } from '../dist/server.js';

const clientFetch = globalThis.fetch;

async function withServer(t) {
  const server = createApp().listen(0, '127.0.0.1');
  t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  await once(server, 'listening');
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

async function rpc(baseUrl, body, token) {
  const response = await clientFetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return { response, body: response.status === 204 ? undefined : await response.json() };
}

test('health and 404 routing are explicit', async (t) => {
  const baseUrl = await withServer(t);
  const healthResponse = await clientFetch(`${baseUrl}/health`);
  assert.equal(healthResponse.status, 200);
  assert.deepEqual(await healthResponse.json(), {
    status: 'ok',
    server: 'graph-audit-mcp',
    version: '1.0.0',
    tools: 6,
    authMode: 'token-passthrough',
    stateless: true,
  });
  const missingResponse = await clientFetch(`${baseUrl}/wrong`);
  assert.equal(missingResponse.status, 404);
  const missing = await missingResponse.json();
  assert.equal(missing.error, 'MCP_ENDPOINT_NOT_FOUND');
});

test('initialize, tools/list, notifications and JSON-RPC validation work', async (t) => {
  const baseUrl = await withServer(t);
  const initialized = await rpc(baseUrl, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(initialized.body.result.serverInfo.name, 'graph-audit-mcp');
  const listed = await rpc(baseUrl, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.equal(listed.body.result.tools.length, 6);
  const notification = await rpc(baseUrl, { jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(notification.response.status, 204);
  const invalid = await rpc(baseUrl, { jsonrpc: '1.0', id: 3, method: 'tools/list' });
  assert.equal(invalid.body.error.code, -32600);
  const unknown = await rpc(baseUrl, { jsonrpc: '2.0', id: 4, method: 'unknown' });
  assert.equal(unknown.body.error.code, -32601);
  const malformedResponse = await clientFetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{"jsonrpc":',
  });
  assert.equal(malformedResponse.status, 400);
  assert.equal((await malformedResponse.json()).error.code, -32700);
});

test('missing authentication and Graph errors are MCP tool failures with safe diagnostics', async (t) => {
  const baseUrl = await withServer(t);
  const missing = await rpc(baseUrl, {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: 'ListSignIns', arguments: {} },
  });
  assert.equal(missing.body.result.isError, true);
  const missingText = JSON.parse(missing.body.result.content[0].text);
  assert.equal(missingText.diagnostics.code, 'AUTHENTICATION_REQUIRED');

  const secretToken = 'secret-that-must-not-leak';
  t.mock.method(globalThis, 'fetch', async () => Response.json({
    error: { code: 'Authorization_RequestDenied', message: `rejected ${secretToken}` },
  }, {
    status: 403,
    headers: { 'request-id': 'graph-request-id', 'retry-after': '30' },
  }));
  const denied = await rpc(baseUrl, {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'ListRiskyUsers', arguments: {} },
  }, secretToken);
  assert.equal(denied.body.result.isError, true);
  const deniedText = denied.body.result.content[0].text;
  assert.equal(deniedText.includes(secretToken), false);
  const failure = JSON.parse(deniedText);
  assert.equal(failure.diagnostics.httpStatus, 403);
  assert.equal(failure.diagnostics.upstream.requestId, 'graph-request-id');
  assert.equal(failure.diagnostics.upstream.retryAfter, '30');
  assert.equal(failure.diagnostics.upstream.errorCode, 'Authorization_RequestDenied');
  assert.match(failure.diagnostics.guidance.join(' '), /IdentityRiskyUser.Read.All/);
});

test('unknown tools and invalid arguments do not call Graph', async (t) => {
  const baseUrl = await withServer(t);
  const fetchMock = t.mock.method(globalThis, 'fetch', () => assert.fail('Graph should not be called'));
  const unknown = await rpc(baseUrl, {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: 'NotATool', arguments: {} },
  });
  assert.equal(unknown.body.error.code, -32601);
  const invalid = await rpc(baseUrl, {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'ListRiskyUsers', arguments: { pageSize: 0 } },
  }, 'token');
  assert.equal(invalid.body.result.isError, true);
  assert.equal(fetchMock.mock.callCount(), 0);
});
