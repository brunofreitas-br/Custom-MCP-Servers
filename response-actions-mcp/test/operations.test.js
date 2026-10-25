const assert = require("node:assert/strict");
const { once } = require("node:events");
const { test } = require("node:test");
const express = require("express");
const { getTool } = require("../dist/toolRegistry.js");
const { toolErrorDetails } = require("../dist/apiClient.js");
require("../dist/tools/index.js");

const base = "https://api.securitycenter.microsoft.com";
const token = "local-operations-token";
const machine = (id, computerDnsName) => ({ id, computerDnsName, onboardingStatus: "Onboarded", lastSeen: "2026-10-25T12:00:00Z" });

function mockApi(t, steps) {
  const requests = [];
  t.mock.method(globalThis, "fetch", async (url, options) => {
    const step = steps[requests.length];
    const request = {
      url: new URL(url), method: options.method, headers: options.headers,
      body: options.body ? JSON.parse(options.body) : undefined,
    };
    requests.push(request);
    assert.ok(step, `Unexpected request: ${url}`);
    assert.equal(request.url.origin, base);
    assert.equal(request.url.pathname, step.path);
    assert.equal(request.method, step.method ?? "GET");
    assert.equal(request.headers.Authorization, `Bearer ${token}`);
    step.check?.(request);
    if (step.error) throw step.error;
    const status = step.status ?? 200;
    if (step.raw !== undefined) return new Response(step.raw, { status, headers: step.headers });
    return Response.json(step.body ?? {}, { status, headers: step.headers });
  });
  t.after(() => assert.equal(requests.length, steps.length));
  return requests;
}

async function invoke(name, args) {
  return getTool(name).handler(args, token);
}

test("short-host lookup is bounded to the exact DNS label and does not select an ambiguous device", async (t) => {
  mockApi(t, [{
    path: "/api/machines",
    body: { value: [machine("mde-1", "pc01.one.example"), machine("mde-2", "pc01.two.example")] },
    check: (request) => {
      assert.equal(request.url.searchParams.get("$filter"), "(computerDnsName eq 'pc01' or startswith(computerDnsName,'pc01.'))");
      assert.equal(request.body, undefined);
    },
  }]);
  const result = await invoke("find_machines", { hostname: "PC01" });
  assert.equal(result.resolution, "AMBIGUOUS");
  assert.equal(result.matchCount, 2);
  assert.deepEqual(result.matches.map((item) => item.machineId), ["mde-1", "mde-2"]);
  assert.equal(result.machineId, undefined);
});

test("FQDN lookup preserves machine metadata and distinguishes MDE IDs from Entra IDs", async (t) => {
  const resource = { ...machine("mde-1", "pc01.example"), aadDeviceId: "entra-other-id" };
  mockApi(t, [{
    path: "/api/machines", body: { value: [resource] },
    check: (request) => assert.equal(request.url.searchParams.get("$filter"), "computerDnsName eq 'pc01.example'"),
  }]);
  const result = await invoke("find_machines", { hostname: "PC01.EXAMPLE." });
  assert.equal(result.resolution, "UNIQUE");
  assert.equal(result.matches[0].machineId, "mde-1");
  assert.equal(result.matches[0].aadDeviceId, "entra-other-id");
  assert.equal(result.matches[0].lastSeen, resource.lastSeen);
});

test("pagination is exhausted before declaring a hostname unique", async (t) => {
  mockApi(t, [
    { path: "/api/machines", body: { value: [machine("mde-1", "pc01.one.example")], "@odata.nextLink": `${base}/api/machines?$skiptoken=next` } },
    { path: "/api/machines", body: { value: [machine("mde-2", "pc01.two.example")] } },
  ]);
  assert.equal((await invoke("find_machines", { hostname: "pc01" })).resolution, "AMBIGUOUS");
});

test("an empty visible machine list is qualified, not proof that the device does not exist", async (t) => {
  mockApi(t, [{ path: "/api/machines", body: { value: [] } }]);
  const result = await invoke("find_machines", { hostname: "pc01" });
  assert.equal(result.resolution, "NOT_FOUND");
  assert.match(result.message, /does not prove/);
});

for (const hostname of ["", " ", "*.example", "https://pc01", "pc01:443", "pc01/path", "pc01' or true", "203.0.113.10", "x".repeat(64)]) {
  test(`invalid hostname ${JSON.stringify(hostname)} never makes a request`, async (t) => {
    mockApi(t, []);
    await assert.rejects(invoke("find_machines", { hostname }), /hostname must be/);
  });
}

for (const next of ["https://outside.example/api/machines", `${base}/api/indicators`, "not-a-url"]) {
  test(`unsafe pagination ${next} never receives an access token`, async (t) => {
    mockApi(t, [{ path: "/api/machines", body: { value: [], "@odata.nextLink": next } }]);
    await assert.rejects(invoke("find_machines", { hostname: "pc01" }), /pagination URL/);
  });
}

test("repeated machine pagination is surfaced instead of looping", async (t) => {
  const page = { value: [], "@odata.nextLink": `${base}/api/machines?$skiptoken=next` };
  mockApi(t, [{ path: "/api/machines", body: page }, { path: "/api/machines", body: page }]);
  await assert.rejects(invoke("find_machines", { hostname: "pc01" }), /repeated pagination URL/);
});

for (const body of [{ wrong: [] }, { value: [{}] }, { value: [machine("mde-1", "pc010.example")] }]) {
  test(`invalid/mismatched machine response ${JSON.stringify(body)} cannot select a device`, async (t) => {
    mockApi(t, [{ path: "/api/machines", body }]);
    await assert.rejects(invoke("find_machines", { hostname: "pc01" }));
  });
}

const actions = [
  ["isolate_device", "isolate", "Isolate", {}],
  ["unisolate_device", "unisolate", "Unisolate", {}],
  ["run_antivirus_scan", "runAntiVirusScan", "RunAntiVirusScan", { scanType: "Full" }],
  ["restrict_app_execution", "restrictCodeExecution", "RestrictCodeExecution", {}],
  ["unrestrict_app_execution", "unrestrictCodeExecution", "UnrestrictCodeExecution", {}],
  ["collect_investigation_package", "collectInvestigationPackage", "CollectInvestigationPackage", {}],
  ["stop_and_quarantine_file", "StopAndQuarantineFile", "StopAndQuarantineFile", { sha1: "a".repeat(40) }],
];
for (const [name, endpoint, type, extra] of actions) {
  test(`${name} preserves its pending action instead of declaring completed success`, async (t) => {
    const resource = { id: "action-1", status: "Pending", machineId: "mde/1", type };
    mockApi(t, [{
      path: `/api/machines/mde%2F1/${endpoint}`, method: "POST", status: 201, body: resource,
      check: (request) => {
        assert.match(request.body.Comment, /SOC-123/);
        if (name === "run_antivirus_scan") assert.equal(request.body.ScanType, "Full");
      },
    }]);
    const result = await invoke(name, { machineId: "mde/1", incidentId: "SOC-123", ...extra });
    assert.equal(result.result, "REQUESTED");
    assert.equal(result.machineActionId, "action-1");
    assert.equal(result.status, "Pending");
    assert.equal(result.completed, false);
    assert.equal(result.succeeded, null);
    assert.deepEqual(result.machineAction, resource);
    assert.match(result.nextStep, /get_machine_action/);
  });
}

for (const [status, result, completed, succeeded] of [
  ["Pending", "REQUESTED", false, null], ["InProgress", "IN_PROGRESS", false, null],
  ["Succeeded", "SUCCEEDED", true, true], ["Failed", "FAILED", true, false],
  ["TimeOut", "TIMED_OUT", true, false], ["Cancelled", "CANCELLED", true, false],
  ["NewStatus", "UNKNOWN", null, null], ["toString", "UNKNOWN", null, null],
]) {
  test(`get_machine_action reports ${status} without submitting any mutation`, async (t) => {
    mockApi(t, [{ path: "/api/machineactions/action%2F1", body: { id: "action/1", status, machineId: "mde-1" } }]);
    const response = await invoke("get_machine_action", { actionId: "action/1" });
    assert.equal(response.result, result);
    assert.equal(response.completed, completed);
    assert.equal(response.succeeded, succeeded);
    assert.equal(response.status, status);
  });
}

for (const [name, args] of [
  ["run_antivirus_scan", { machineId: "mde-1", incidentId: "x", scanType: "unknown" }],
  ["run_antivirus_scan", { machineId: "", incidentId: "x" }],
  ["run_antivirus_scan", { hostname: "pc01", incidentId: "x" }],
  ["isolate_device", { machineId: "mde-1", incidentId: "x", isolationType: "none" }],
  ["get_machine_action", { actionId: "" }],
]) {
  test(`${name} rejects invalid operation inputs before making a request`, async (t) => {
    mockApi(t, []);
    await assert.rejects(invoke(name, args));
  });
}

test("a mismatched action ID cannot be reported as the requested action's status", async (t) => {
  mockApi(t, [{ path: "/api/machineactions/expected", body: { id: "other", status: "Succeeded" } }]);
  await assert.rejects(invoke("get_machine_action", { actionId: "expected" }), /different machine action/);
});

for (const status of [403, 404, 429]) {
  test(`HTTP ${status} retains request IDs and gives non-speculative guidance`, async (t) => {
    mockApi(t, [{
      path: "/api/machineactions/action-1", status,
      body: { error: { code: "TestFailure", message: `Failure without leaking ${token}` } },
      headers: { "request-id": "server-request", "retry-after": "30" },
    }]);
    await assert.rejects(invoke("get_machine_action", { actionId: "action-1" }), (error) => {
      const details = toolErrorDetails(error, "get_machine_action", { actionId: "action-1" });
      assert.equal(details.diagnostics.httpStatus, status);
      assert.equal(details.diagnostics.upstream.requestId, "server-request");
      assert.equal(details.diagnostics.upstream.retryAfter, "30");
      assert.equal(details.diagnostics.upstream.method, "GET");
      assert.equal(details.diagnostics.automaticRetryAllowed, false);
      assert.equal(JSON.stringify(details).includes(token), false);
      return true;
    });
  });
}

test("a network failure after a scan submission is explicit and never replayed", async (t) => {
  mockApi(t, [{ path: "/api/machines/mde-1/runAntiVirusScan", method: "POST", error: new TypeError("network") }]);
  await assert.rejects(invoke("run_antivirus_scan", { machineId: "mde-1", incidentId: "SOC-1" }), (error) => {
    assert.equal(error.diagnostics.code, "UPSTREAM_NETWORK_ERROR");
    assert.equal(error.diagnostics.automaticRetryAllowed, false);
    return true;
  });
});

test("HTML success responses do not become successful machine actions", async (t) => {
  mockApi(t, [{ path: "/api/machines/mde-1/runAntiVirusScan", method: "POST", raw: "<html>unexpected</html>" }]);
  await assert.rejects(invoke("run_antivirus_scan", { machineId: "mde-1", incidentId: "SOC-1" }), (error) => {
    assert.equal(error.diagnostics.code, "INVALID_UPSTREAM_RESPONSE");
    return true;
  });
});

test("HTTP MCP exposes read-only lookups, action tracking, structured errors and route diagnostics", async (t) => {
  const clientFetch = globalThis.fetch;
  mockApi(t, [
    { path: "/api/machines", body: { value: [machine("mde-1", "pc01.example")] } },
    { path: "/api/machineactions/action-1", body: { id: "action-1", status: "Succeeded" } },
    { path: "/api/machineactions/missing", status: 404, body: { error: { code: "ResourceNotFound" } }, headers: { "request-id": "tracking-404" } },
  ]);
  const listen = express.application.listen;
  let server;
  t.mock.method(express.application, "listen", function (_port, callback) {
    server = listen.call(this, 0, "127.0.0.1", callback);
    return server;
  });
  require("../dist/server.js");
  t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  if (!server.listening) await once(server, "listening");
  const address = server.address();
  const url = `http://127.0.0.1:${address.port}`;
  async function rpc(collection, name, args) {
    return (await clientFetch(`${url}/mcp/${collection}`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    })).json();
  }
  const found = await rpc("devices", "find_machines", { hostname: "pc01.example" });
  assert.equal(JSON.parse(found.result.content[0].text).resolution, "UNIQUE");
  const tracked = await rpc("devices", "get_machine_action", { actionId: "action-1" });
  assert.equal(JSON.parse(tracked.result.content[0].text).result, "SUCCEEDED");
  const denied = await rpc("identity", "get_machine_action", { actionId: "action-1" });
  assert.equal(denied.error.code, -32601);
  const missing = await rpc("devices", "get_machine_action", { actionId: "missing" });
  assert.equal(missing.error.code, -32000);
  assert.equal(missing.error.data.diagnostics.httpStatus, 404);
  assert.equal(missing.error.data.diagnostics.upstream.requestId, "tracking-404");
  const wrongRoute = await clientFetch(`${url}/mcp`, { method: "POST" });
  assert.equal(wrongRoute.status, 404);
  assert.equal((await wrongRoute.json()).error, "MCP_ENDPOINT_NOT_FOUND");
});
