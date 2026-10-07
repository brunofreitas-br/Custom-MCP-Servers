const assert = require("node:assert/strict");
const { once } = require("node:events");
const { test } = require("node:test");
const express = require("express");
const { getTool, listTools } = require("../dist/toolRegistry.js");
require("../dist/tools/index.js");

function mockApi(t, result = { id: "resource-1", status: "Pending" }, status = 200) {
  const requests = [];
  t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.ok(["https://api.securitycenter.microsoft.com", "https://graph.microsoft.com"].includes(new URL(url).origin));
    requests.push({
      url: new URL(url),
      method: options.method,
      headers: options.headers,
      body: options.body === undefined ? undefined : JSON.parse(options.body),
    });
    return status === 204 ? new Response(null, { status }) : Response.json(result, { status });
  });
  return requests;
}

async function invoke(name, args) {
  const tool = getTool(name);
  assert.ok(tool, `Missing tool ${name}`);
  return tool.handler(args, "response-test-token");
}

const indicatorArgs = {
  indicatorType: "Url",
  indicatorValue: "https://blocked.example/download",
  incidentId: "SOC-123",
  title: "Confirmed malicious indicator",
  description: "Containment following investigation",
  scope: "deviceGroups",
  rbacGroupNames: ["SOC Lab"],
};

const quarantineArgs = {
  machineId: "machine-1",
  sha1: "a".repeat(40),
  incidentId: "SOC-123",
};

test("discovery preserves all existing tools and keeps new actions in the Defender collection", () => {
  assert.deepEqual(listTools().map((tool) => tool.name).sort(), [
    "block_user", "unblock_user", "revoke_sessions", "reset_user_password",
    "isolate_device", "unisolate_device", "run_antivirus_scan", "restrict_app_execution",
    "unrestrict_app_execution", "collect_investigation_package",
    "block_indicator", "stop_and_quarantine_file",
  ].sort());
  assert.equal(listTools("identity").length, 4);
  assert.equal(listTools("devices").length, 8);
  for (const name of ["block_indicator", "stop_and_quarantine_file"]) {
    assert.equal(getTool(name, "identity"), undefined);
    assert.ok(getTool(name, "devices"));
    assert.equal(getTool(name).inputSchema.additionalProperties, false);
  }
});

for (const [indicatorType, indicatorValue, action] of [
  ["Url", "https://blocked.example/download", "Block"],
  ["DomainName", "blocked.example", "Block"],
  ["IpAddress", "203.0.113.10", "Block"],
  ["IpAddress", "2001:db8::1", "Block"],
  ["FileSha1", "a".repeat(40), "BlockAndRemediate"],
  ["FileSha256", "b".repeat(64), "BlockAndRemediate"],
  ["FileMd5", "c".repeat(32), "BlockAndRemediate"],
  ["CertificateThumbprint", "d".repeat(40), "BlockAndRemediate"],
]) {
  test(`blocks ${indicatorType} ${indicatorValue} using the supported action`, async (t) => {
    const resource = { id: "indicator-1", action, indicatorType, indicatorValue };
    const requests = mockApi(t, resource);
    const result = await invoke("block_indicator", { ...indicatorArgs, indicatorType, indicatorValue });
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, "POST");
    assert.equal(requests[0].url.href, "https://api.securitycenter.microsoft.com/api/indicators");
    assert.equal(requests[0].headers.Authorization, "Bearer response-test-token");
    assert.deepEqual(requests[0].body, {
      indicatorType,
      indicatorValue,
      action,
      title: indicatorArgs.title,
      description: `${indicatorArgs.description}\nIncident: SOC-123\nRequested at: ${result.timestamp}`,
      rbacGroupNames: ["SOC Lab"],
    });
    assert.equal(result.result, "SUBMITTED");
    assert.equal(result.scope, "deviceGroups");
    assert.deepEqual(result.indicator, resource);
  });
}

test("tenant-wide blocking is explicit and preserves optional expiration, severity and false alert flag", async (t) => {
  const requests = mockApi(t);
  const { rbacGroupNames, ...args } = indicatorArgs;
  await invoke("block_indicator", {
    ...args,
    scope: "allDevices",
    expirationTime: "2099-06-01T10:00:00-03:00",
    severity: "High",
    generateAlert: false,
  });
  assert.deepEqual(requests[0].body.rbacGroupNames, []);
  assert.equal(requests[0].body.expirationTime, "2099-06-01T10:00:00-03:00");
  assert.equal(requests[0].body.severity, "High");
  assert.equal(requests[0].body.generateAlert, false);
  assert.equal(Object.hasOwn(requests[0].body, "scope"), false);
  assert.equal(Object.hasOwn(requests[0].body, "incidentId"), false);
});

test("quarantine uses machine ID and SHA-1 and returns the pending machine action, not completed success", async (t) => {
  const action = { id: "action-1", status: "Pending", type: "StopAndQuarantineFile" };
  const requests = mockApi(t, action, 201);
  const result = await invoke("stop_and_quarantine_file", {
    ...quarantineArgs,
    machineId: "machine/with?#",
    comment: "Confirmed malicious executable",
  });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, "POST");
  assert.equal(requests[0].url.href, "https://api.securitycenter.microsoft.com/api/machines/machine%2Fwith%3F%23/StopAndQuarantineFile");
  assert.equal(requests[0].headers.Authorization, "Bearer response-test-token");
  assert.deepEqual(requests[0].body, {
    Sha1: quarantineArgs.sha1,
    Comment: `Stop and quarantine file - Incident SOC-123 - ${result.timestamp} - Confirmed malicious executable`,
  });
  assert.equal(result.result, "REQUESTED");
  assert.equal(result.incidentId, "SOC-123");
  assert.deepEqual(result.machineAction, action);
});

const invalidIndicators = [
  ["missing type", { indicatorType: undefined }, /indicatorType must be/],
  ["unsupported type", { indicatorType: "FileSha512" }, /indicatorType must be one of/],
  ["empty value", { indicatorValue: " " }, /indicatorValue must be/],
  ["non-HTTP URL", { indicatorValue: "ftp://blocked.example" }, /HTTP\(S\)/],
  ["URL with credentials", { indicatorValue: "https://user:pass@blocked.example" }, /credentials/],
  ["malformed URL", { indicatorValue: "not a URL" }, /valid HTTP/],
  ["CIDR range", { indicatorType: "IpAddress", indicatorValue: "203.0.113.0/24" }, /single IP address/],
  ["invalid IP", { indicatorType: "IpAddress", indicatorValue: "999.1.2.3" }, /single IP address/],
  ["URL as domain", { indicatorType: "DomainName", indicatorValue: "https://blocked.example" }, /ASCII domain/],
  ["wildcard domain", { indicatorType: "DomainName", indicatorValue: "*.blocked.example" }, /ASCII domain/],
  ["IP as domain", { indicatorType: "DomainName", indicatorValue: "203.0.113.10" }, /ASCII domain/],
  ["invalid SHA-1", { indicatorType: "FileSha1", indicatorValue: "x".repeat(40) }, /40 hexadecimal/],
  ["invalid SHA-256 length", { indicatorType: "FileSha256", indicatorValue: "a".repeat(40) }, /64 hexadecimal/],
  ["invalid MD5 length", { indicatorType: "FileMd5", indicatorValue: "a".repeat(31) }, /32 hexadecimal/],
  ["invalid certificate thumbprint", { indicatorType: "CertificateThumbprint", indicatorValue: "a".repeat(64) }, /40 hexadecimal/],
  ["missing incident", { incidentId: undefined }, /incidentId must be/],
  ["blank title", { title: " " }, /title must be/],
  ["blank description", { description: "" }, /description must be/],
  ["missing scope", { scope: undefined }, /scope must be/],
  ["unknown scope", { scope: "automatic" }, /scope must be/],
  ["missing groups", { rbacGroupNames: undefined }, /non-empty rbacGroupNames/],
  ["empty groups", { rbacGroupNames: [] }, /non-empty rbacGroupNames/],
  ["blank group", { rbacGroupNames: [" "] }, /rbacGroupNames item/],
  ["non-string group", { rbacGroupNames: [123] }, /rbacGroupNames item/],
  ["conflicting tenant-wide scope", { scope: "allDevices" }, /Do not provide rbacGroupNames/],
  ["invalid expiration", { expirationTime: "not a date" }, /future ISO 8601/],
  ["missing expiration timezone", { expirationTime: "2099-01-01T00:00:00" }, /future ISO 8601/],
  ["out-of-range expiration hour", { expirationTime: "2099-01-01T24:00:00Z" }, /future ISO 8601/],
  ["past expiration", { expirationTime: "2000-01-01T00:00:00Z" }, /future ISO 8601/],
  ["expiration at the current instant", { expirationTime: new Date().toISOString() }, /future ISO 8601/],
  ["nonexistent calendar date", { expirationTime: "2099-02-29T00:00:00Z" }, /valid calendar date/],
  ["invalid severity", { severity: "Critical" }, /severity must be one of/],
  ["string boolean", { generateAlert: "false" }, /generateAlert must be a boolean/],
  ["unsupported action override", { action: "Allowed" }, /Unsupported argument/],
];

for (const [label, overrides, message] of invalidIndicators) {
  test(`rejects indicator ${label} without submitting a block`, async (t) => {
    const requests = mockApi(t);
    await assert.rejects(invoke("block_indicator", { ...indicatorArgs, ...overrides }), message);
    assert.equal(requests.length, 0);
  });
}

for (const [label, overrides, message] of [
  ["missing machine", { machineId: undefined }, /machineId must be/],
  ["missing hash", { sha1: undefined }, /sha1 must be/],
  ["wrong hash length", { sha1: "a".repeat(64) }, /40 hexadecimal/],
  ["non-hexadecimal hash", { sha1: "z".repeat(40) }, /40 hexadecimal/],
  ["missing incident", { incidentId: "" }, /incidentId must be/],
  ["blank comment", { comment: " " }, /comment must be/],
  ["file path instead of hash", { filePath: "C:\\temp\\file.exe" }, /Unsupported argument/],
]) {
  test(`rejects quarantine ${label} without requesting a machine action`, async (t) => {
    const requests = mockApi(t);
    await assert.rejects(invoke("stop_and_quarantine_file", { ...quarantineArgs, ...overrides }), message);
    assert.equal(requests.length, 0);
  });
}

for (const name of ["block_indicator", "stop_and_quarantine_file"]) {
  test(`${name} rejects non-object arguments`, async (t) => {
    const requests = mockApi(t);
    await assert.rejects(invoke(name, null), /arguments must be an object/);
    await assert.rejects(invoke(name, []), /arguments must be an object/);
    assert.equal(requests.length, 0);
  });
  for (const status of [403, 429]) {
    test(`${name} propagates HTTP ${status} instead of reporting success`, async (t) => {
      const requests = mockApi(t, { error: { message: "Action rejected" } }, status);
      await assert.rejects(invoke(name, name === "block_indicator" ? indicatorArgs : quarantineArgs), new RegExp(`\\(${status}\\)`));
      assert.equal(requests.length, 1);
    });
  }
}

for (const [name, args, resource, status] of [
  ["block_indicator", indicatorArgs, {}, 200],
  ["block_indicator", indicatorArgs, null, 200],
  ["block_indicator", indicatorArgs, {}, 204],
  ["stop_and_quarantine_file", quarantineArgs, {}, 201],
  ["stop_and_quarantine_file", quarantineArgs, null, 201],
  ["stop_and_quarantine_file", quarantineArgs, { id: "action-1" }, 201],
  ["stop_and_quarantine_file", quarantineArgs, {}, 204],
]) {
  test(`${name} rejects an incomplete HTTP ${status} result ${JSON.stringify(resource)}`, async (t) => {
    const requests = mockApi(t, resource, status);
    await assert.rejects(invoke(name, args), /Defender returned an invalid .* response/);
    assert.equal(requests.length, 1);
  });
}

test("existing device and identity action payloads remain unchanged", async (t) => {
  const requests = mockApi(t, {}, 204);
  const isolated = await invoke("isolate_device", { machineId: "machine-1", incidentId: "SOC-123" });
  assert.equal(isolated.result, "SUCCESS");
  assert.equal(requests[0].url.pathname, "/api/machines/machine-1/isolate");
  assert.equal(requests[0].body.IsolationType, "Full");
  const blocked = await invoke("block_user", { userId: "analyst@example.com", incidentId: "SOC-123" });
  assert.equal(blocked.result, "SUCCESS");
  assert.equal(requests[1].url.origin, "https://graph.microsoft.com");
  assert.equal(requests[1].method, "PATCH");
  assert.deepEqual(requests[1].body, { accountEnabled: false });
});

test("HTTP MCP routes both new tools only through the existing Defender endpoint", async (t) => {
  const clientFetch = globalThis.fetch;
  const resource = { id: "operation-1", status: "Pending" };
  const requests = mockApi(t, resource);
  const listen = express.application.listen;
  let server;
  t.mock.method(express.application, "listen", function (_port, callback) {
    server = listen.call(this, 0, "127.0.0.1", callback);
    return server;
  });
  require("../dist/server.js");
  assert.ok(server);
  t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  if (!server.listening) await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;

  async function rpc(collection, method, params, authenticated = true) {
    const response = await clientFetch(`${base}/mcp/${collection}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(authenticated ? { Authorization: "Bearer protocol-test-token" } : {}),
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    assert.equal(response.status, 200);
    return response.json();
  }

  const health = await (await clientFetch(`${base}/health`)).json();
  assert.equal(health.totalTools, 12);
  assert.equal((await rpc("devices", "initialize")).result.protocolVersion, "2025-03-26");
  assert.equal((await rpc("identity", "tools/list")).result.tools.length, 4);
  assert.equal((await rpc("devices", "tools/list")).result.tools.length, 8);
  const indicator = await rpc("devices", "tools/call", { name: "block_indicator", arguments: indicatorArgs });
  assert.equal(JSON.parse(indicator.result.content[0].text).result, "SUBMITTED");
  const quarantine = await rpc("devices", "tools/call", { name: "stop_and_quarantine_file", arguments: quarantineArgs });
  const result = JSON.parse(quarantine.result.content[0].text);
  assert.equal(result.result, "REQUESTED");
  assert.deepEqual(result.machineAction, resource);
  for (const name of ["block_indicator", "stop_and_quarantine_file"]) {
    assert.equal((await rpc("identity", "tools/call", { name, arguments: {} })).error.code, -32601);
  }
  const unauthenticated = await rpc("devices", "tools/call", {
    name: "block_indicator", arguments: indicatorArgs,
  }, false);
  assert.equal(unauthenticated.error.code, -32000);
  const invalid = await rpc("devices", "tools/call", {
    name: "block_indicator", arguments: { ...indicatorArgs, scope: "automatic" },
  });
  assert.equal(invalid.error.code, -32000);
  assert.equal(requests.length, 2);
  assert.ok(requests.every((request) => request.headers.Authorization === "Bearer protocol-test-token"));
});
