import assert from 'node:assert/strict';
import { once } from 'node:events';
import { test } from 'node:test';
import express from 'express';
import { userTokenStore } from '../dist/apiClient.js';
import { caseManagementEnabled, CaseEnrichmentError } from '../dist/caseManagement.js';
import { getTool, listTools } from '../dist/toolRegistry.js';
import { registerAllTools } from '../dist/tools/index.js';

process.env.CASE_MANAGEMENT_ENABLED = 'true';
registerAllTools();

const namespace = 'microsoft.graph.security.caseManagement';
const casesPath = '/beta/security/caseManagement/cases';
const incidentCasesPath = `${casesPath}/${namespace}.incidentCase`;
const statusesPath = '/beta/security/caseManagement/caseTypeConfigurations/incidentCase/statuses';
const incidentPath = '/v1.0/security/incidents/912751';
const incidentCase = {
  '@odata.type': `#${namespace}.incidentCase`,
  id: 'case-distinct-id',
  incidentId: 912751,
  displayName: 'Persistence on endpoint',
  status: 'Active',
  severity: 'medium',
  createdDateTime: '2026-10-13T18:00:00Z',
  lastModifiedDateTime: '2026-10-14T12:00:00Z',
};
const genericCase = {
  '@odata.type': `#${namespace}.genericCase`,
  id: 'generic-work',
  displayName: 'Follow-up work',
  status: 'Open',
};
const statusTree = {
  value: [
    { id: 'opaque-active-id', displayName: 'Active', customStatuses: [{ displayName: 'Triage', isFinal: false }] },
    { id: 'opaque-resolved-id', displayName: 'Resolved', customStatuses: [{ displayName: 'Closed - Fixed', isFinal: true }] },
    { id: 'opaque-redirected-id', displayName: 'Redirected', customStatuses: [] },
  ],
};

function mockGraph(t, steps) {
  const requests = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    const step = steps[requests.length];
    const request = {
      url: new URL(url),
      method: options.method,
      headers: options.headers,
      body: options.body === undefined ? undefined : JSON.parse(options.body),
    };
    requests.push(request);
    assert.equal(request.url.origin, 'https://graph.microsoft.com');
    assert.ok(step, `Unexpected request ${request.method} ${url}`);
    assert.equal(request.url.pathname, step.path);
    assert.equal(request.method, step.method ?? 'GET');
    step.check?.(request);
    if (step.error) throw step.error;
    const status = step.status ?? 200;
    if (step.raw !== undefined) return new Response(step.raw, { status });
    if (status === 202 || status === 204) return new Response(null, { status });
    return Response.json(step.body ?? {}, { status });
  });
  t.after(() => assert.equal(requests.length, steps.length, 'All planned requests must be executed exactly once'));
  return requests;
}

async function invoke(name, args, token = 'cases-test-token') {
  const tool = getTool(name);
  assert.ok(tool, `Missing tool ${name}`);
  return userTokenStore.run(token, () => tool.handler(args));
}

function lookup(body = { value: [incidentCase] }) {
  return {
    path: incidentCasesPath,
    body,
    check: (request) => {
      assert.equal(request.url.searchParams.get('$filter'), 'incidentId eq 912751');
      assert.equal(request.url.searchParams.get('$top'), '2');
    },
  };
}

function setting(t, value) {
  const original = process.env.CASE_MANAGEMENT_ENABLED;
  if (value === undefined) delete process.env.CASE_MANAGEMENT_ENABLED;
  else process.env.CASE_MANAGEMENT_ENABLED = value;
  t.after(() => {
    if (original === undefined) delete process.env.CASE_MANAGEMENT_ENABLED;
    else process.env.CASE_MANAGEMENT_ENABLED = original;
  });
}

test('Cases are primary by default and discovery has 14 tools', (t) => {
  setting(t, undefined);
  assert.equal(caseManagementEnabled(), true);
  assert.equal(listTools().length, 14);
  assert.ok(getTool('UpdateIncident'));
  assert.ok(getTool('UpdateCase'));
});

test('GetIncidentById casts the collection and never conflates Case ID with Incident ID', async (t) => {
  const requests = mockGraph(t, [lookup()]);
  const result = await invoke('GetIncidentById', { incidentId: '912751' });
  assert.equal(result.id, '912751');
  assert.equal(result.caseId, 'case-distinct-id');
  assert.equal(result.caseStatus, 'Active');
  assert.equal(result.lastUpdateDateTime, incidentCase.lastModifiedDateTime);
  assert.deepEqual(result.caseDetails, incidentCase);
  assert.equal(result._mcp.source, 'cases');
  assert.equal(result._mcp.apiVersion, 'beta');
  assert.equal(result._mcp.preview, true);
  assert.equal(requests[0].headers.Authorization, 'Bearer cases-test-token');
});

test('GetCaseById uses and encodes the actual Case ID', async (t) => {
  const id = 'case/with?#';
  mockGraph(t, [{ path: `${casesPath}/case%2Fwith%3F%23`, body: { ...incidentCase, id } }]);
  const result = await invoke('GetCaseById', { caseId: id });
  assert.equal(result.id, id);
  assert.equal(result.caseId, id);
  assert.equal(result.incidentId, '912751');
});

test('an unknown Case ID is not guessed to be an Incident ID', async (t) => {
  mockGraph(t, [{ path: `${casesPath}/912751`, status: 404, body: { error: 'Case not found' } }]);
  await assert.rejects(invoke('GetCaseById', { caseId: '912751' }), /HTTP 404/);
});

for (const [label, step, reason] of [
  ['no matching case', lookup({ value: [] }), 'not-found'],
  ['Cases HTTP 404', { path: incidentCasesPath, status: 404, body: { error: 'Preview unavailable' } }, 'http-404'],
]) {
  test(`reads fall back on ${label} and preserve the legacy expand request`, async (t) => {
    const legacy = { id: '912751', status: 'resolved', alerts: [{ id: 'alert-1' }] };
    mockGraph(t, [
      step,
      { path: incidentPath, body: legacy, check: (request) => assert.equal(request.url.searchParams.get('$expand'), 'alerts') },
    ]);
    const result = await invoke('GetIncidentById', { incidentId: '912751', includeAlertsData: true });
    assert.equal(result._mcp.source, 'incidents');
    assert.equal(result._mcp.fallback.reason, reason);
    assert.ok(result._mcp.fallback.primaryError);
    assert.equal(result.id, legacy.id);
    assert.deepEqual(result.alerts, legacy.alerts);
    assert.equal(result.caseId, undefined);
  });
}

for (const status of [400, 401, 403, 429, 500, 503]) {
  test(`HTTP ${status} from Cases is surfaced, never hidden by a read fallback`, async (t) => {
    mockGraph(t, [{ path: incidentCasesPath, status, body: { error: 'Primary failure' } }]);
    await assert.rejects(invoke('GetIncidentById', { incidentId: '912751' }), new RegExp(`HTTP ${status}`));
  });
}

test('a failed legacy fallback reports both failures', async (t) => {
  mockGraph(t, [
    { path: incidentCasesPath, status: 404, body: { error: 'Case request-id A' } },
    { path: incidentPath, status: 404, body: { error: 'Incident request-id B' } },
  ]);
  await assert.rejects(invoke('GetIncidentById', { incidentId: '912751' }), /Cases path failed:.*Case request-id A.*Incident fallback failed:.*Incident request-id B/);
});

test('non-numeric legacy incident identifiers retain their original encoded path', async (t) => {
  mockGraph(t, [{ path: '/v1.0/security/incidents/opaque%2Fid', body: { id: 'opaque/id' } }]);
  const result = await invoke('GetIncidentById', { incidentId: 'opaque/id' });
  assert.equal(result.id, 'opaque/id');
  assert.equal(result._mcp.fallback.reason, 'legacy-compatibility');
});

test('Int64 lookup values are never converted to rounded JavaScript numbers', async (t) => {
  const id = '9223372036854775807';
  mockGraph(t, [{
    path: incidentCasesPath,
    body: { value: [{ ...incidentCase, incidentId: id }] },
    check: (request) => assert.equal(request.url.searchParams.get('$filter'), `incidentId eq ${id}`),
  }]);
  assert.equal((await invoke('GetIncidentById', { incidentId: id })).id, id);
});

for (const [label, value, message] of [
  ['a rounded numeric incident ID', { ...incidentCase, incidentId: 9007199254740992 }, /rounded ID/],
  ['a different incident ID', { ...incidentCase, incidentId: 1 }, /different incidentId/],
  ['an unexpected case type', { ...incidentCase, '@odata.type': '#other.case' }, /unexpected case type/],
]) {
  test(`rejects ${label} without guessing a resource or falling back`, async (t) => {
    mockGraph(t, [lookup({ value: [value] })]);
    await assert.rejects(invoke('GetIncidentById', { incidentId: '912751' }), message);
  });
}

test('ambiguous incident-to-case mappings stop before any write', async (t) => {
  mockGraph(t, [lookup({ value: [incidentCase, { ...incidentCase, id: 'second-case' }] })]);
  await assert.rejects(invoke('UpdateIncident', { incidentId: '912751', status: 'resolved' }), /Multiple incident cases/);
});

test('incident lookup follows continuation pages before declaring no match', async (t) => {
  const next = `https://graph.microsoft.com${incidentCasesPath}?$skiptoken=cursor`;
  mockGraph(t, [lookup({ value: [], '@odata.nextLink': next }), { path: incidentCasesPath, body: { value: [incidentCase] } }]);
  assert.equal((await invoke('GetIncidentById', { incidentId: '912751' })).caseId, incidentCase.id);
});

for (const next of [
  `https://outside.example${incidentCasesPath}?$skiptoken=cursor`,
  'https://graph.microsoft.com/v1.0/security/incidents?$skiptoken=cursor',
  'not-a-url',
]) {
  test(`rejects pagination URL ${next} without forwarding a token`, async (t) => {
    mockGraph(t, [lookup({ value: [], '@odata.nextLink': next })]);
    await assert.rejects(invoke('GetIncidentById', { incidentId: '912751' }), /pagination URL/);
  });
}

test('repeated continuation URLs do not loop or trigger a legacy fallback', async (t) => {
  const next = `https://graph.microsoft.com${incidentCasesPath}?$skiptoken=cursor`;
  const page = { value: [], '@odata.nextLink': next };
  mockGraph(t, [lookup(page), { path: incidentCasesPath, body: page }]);
  await assert.rejects(invoke('GetIncidentById', { incidentId: '912751' }), /repeated pagination URL/);
});

test('alert enrichment keeps Cases primary and uses the documented legacy expand endpoint', async (t) => {
  mockGraph(t, [
    lookup(),
    { path: incidentPath, body: { id: '912751', alerts: [{ id: 'alert-1' }] }, check: (request) => assert.equal(request.url.searchParams.get('$expand'), 'alerts') },
  ]);
  const result = await invoke('GetIncidentById', { incidentId: '912751', includeAlertsData: true });
  assert.equal(result._mcp.source, 'cases');
  assert.deepEqual(result.alerts, [{ id: 'alert-1' }]);
});

test('failed alert enrichment explicitly preserves the found Case and is not another read fallback', async (t) => {
  mockGraph(t, [lookup(), { path: incidentPath, status: 404, body: { error: 'Alerts inaccessible' } }]);
  await assert.rejects(invoke('GetIncidentById', { incidentId: '912751', includeAlertsData: true }), (error) => {
    assert.ok(error instanceof CaseEnrichmentError);
    assert.equal(error.partialResult.caseId, incidentCase.id);
    assert.match(error.message, /Case found, but correlated alerts/);
    return true;
  });
});

test('ListCases supports exact incident references, escaped analyst strings and the 100-item boundary', async (t) => {
  mockGraph(t, [{
    path: incidentCasesPath,
    body: { value: [incidentCase], '@odata.nextLink': `https://graph.microsoft.com${incidentCasesPath}?$skip=100` },
    check: (request) => {
      assert.equal(request.url.searchParams.get('$filter'), "assignedTo eq 'o''brien@example.com' and severity eq 'medium' and incidentId eq 912751");
      assert.equal(request.url.searchParams.get('$top'), '100');
      assert.equal(request.url.searchParams.get('$skip'), '0');
    },
  }]);
  const result = await invoke('ListCases', { incidentId: '912751', assignedTo: "o'brien@example.com", severity: 'medium', top: 100, skip: 0 });
  assert.equal(result.value[0].id, incidentCase.id);
  assert.ok(result['@odata.nextLink']);
});

test('ListIncidents translates the tenant status and legacy ordering while preserving incident IDs', async (t) => {
  mockGraph(t, [
    { path: statusesPath, body: statusTree },
    {
      path: incidentCasesPath,
      body: { value: [incidentCase] },
      check: (request) => {
        assert.equal(request.url.searchParams.get('$filter'), "severity eq 'medium' and (status eq 'Active' or status eq 'Triage')");
        assert.equal(request.url.searchParams.get('$orderby'), 'lastModifiedDateTime desc');
        assert.equal(request.url.searchParams.get('$top'), '5');
      },
    },
  ]);
  const result = await invoke('ListIncidents', { severity: 'medium', status: 'active', orderBy: 'lastUpdateDateTime desc', top: 5 });
  assert.equal(result.value[0].id, '912751');
  assert.equal(result.value[0].caseId, incidentCase.id);
  assert.equal(result._mcp.source, 'cases');
});

test('an empty first incident-case page falls back to the original incident list', async (t) => {
  mockGraph(t, [
    { path: incidentCasesPath, body: { value: [] } },
    { path: '/v1.0/security/incidents', body: { value: [{ id: '912751' }] }, check: (request) => assert.equal(request.url.searchParams.get('$top'), '5') },
  ]);
  const result = await invoke('ListIncidents', { top: 5 });
  assert.equal(result._mcp.source, 'incidents');
  assert.equal(result._mcp.fallback.reason, 'not-found');
});

test('legacy active filters include custom statuses from that tenant lifecycle family', async (t) => {
  mockGraph(t, [
    { path: statusesPath, body: statusTree },
    {
      path: incidentCasesPath,
      body: { value: [{ ...incidentCase, status: 'Triage' }] },
      check: (request) => assert.equal(request.url.searchParams.get('$filter'), "(status eq 'Active' or status eq 'Triage')"),
    },
  ]);
  const result = await invoke('ListIncidents', { status: 'active' });
  assert.equal(result.value[0].caseStatus, 'Triage');
  assert.equal(result.value[0].id, '912751');
});

test('an empty later page is an end-of-list, not a source switch', async (t) => {
  mockGraph(t, [{ path: incidentCasesPath, body: { value: [] } }]);
  const result = await invoke('ListIncidents', { skip: 20 });
  assert.equal(result._mcp.source, 'cases');
  assert.deepEqual(result.value, []);
});

test('legacy free-text queries remain intact and do not silently drop search', async (t) => {
  mockGraph(t, [{
    path: '/v1.0/security/incidents',
    body: { value: [] },
    check: (request) => assert.equal(request.url.searchParams.get('$search'), '"malware"'),
  }]);
  assert.equal((await invoke('ListIncidents', { search: 'malware' }))._mcp.fallback.reason, 'legacy-compatibility');
});

test('unsupported legacy ordering is preserved before requesting tenant status configuration', async (t) => {
  mockGraph(t, [{
    path: '/v1.0/security/incidents',
    body: { value: [] },
    check: (request) => assert.equal(request.url.searchParams.get('$orderby'), 'severity desc'),
  }]);
  const result = await invoke('ListIncidents', { status: 'active', orderBy: 'severity desc' });
  assert.equal(result._mcp.fallback.reason, 'legacy-compatibility');
});

const invalidCaseArguments = [
  ['ListCases', { top: 101 }, /between 1 and 100/],
  ['ListCases', { top: 0 }, /between 1 and 100/],
  ['ListCases', { top: 1.5 }, /between 1 and 100/],
  ['ListCases', { skip: -1 }, /greater than or equal to 0/],
  ['ListCases', { incidentId: '912751 or 1 eq 1' }, /Int64/],
  ['ListCases', { incidentId: '9223372036854775808' }, /Int64/],
  ['ListCases', { caseType: 'genericCase', incidentId: '1' }, /only supported for incidentCase/],
  ['ListCases', { caseType: 'genericCase', severity: 'high' }, /only supported for incidentCase/],
  ['ListCases', { caseType: 'other' }, /caseType must be/],
  ['ListCases', { createdAfter: 'not a date' }, /ISO 8601/],
  ['ListCases', { severity: 'critical' }, /severity must be one of/],
  ['ListCases', { orderBy: 'severity desc' }, /orderBy supports/],
  ['ListCases', { customFields: {} }, /Unsupported argument/],
  ['GetCaseById', { caseId: '' }, /caseId must be/],
  ['GetCaseById', { caseId: 'x', includeAlertsData: 'true' }, /must be a boolean/],
  ['ResolveCaseReference', { referenceType: 'auto', referenceId: '1' }, /referenceType must be/],
  ['ResolveCaseReference', { referenceType: 'case', referenceId: '' }, /referenceId must be/],
  ['UpdateCase', { caseId: 'x' }, /at least one field/],
  ['UpdateCase', { caseId: 'x', status: '' }, /status must be/],
  ['UpdateCase', { caseId: 'x', assignedTo: null }, /assignedTo must be/],
  ['UpdateCase', { caseId: 'x', description: 'unsupported' }, /Unsupported update field/],
];

for (const [name, args, message] of invalidCaseArguments) {
  test(`${name} rejects invalid arguments ${JSON.stringify(args)} before an API call`, async (t) => {
    mockGraph(t, []);
    await assert.rejects(invoke(name, args), message);
  });
}

test('ResolveCaseReference distinguishes case and incident references', async (t) => {
  mockGraph(t, [lookup(), { path: `${casesPath}/${incidentCase.id}`, body: incidentCase }]);
  for (const [referenceType, referenceId] of [['incident', '912751'], ['case', incidentCase.id]]) {
    const result = await invoke('ResolveCaseReference', { referenceType, referenceId });
    assert.equal(result.caseId, incidentCase.id);
    assert.equal(result.incidentId, '912751');
  }
});

test('a generic Case resolves all related incidents across pages without choosing the first', async (t) => {
  const path = `${casesPath}/${genericCase.id}/relations`;
  const relation = (id) => ({ '@odata.type': `#${namespace}.incidentRelation`, relatedResourceId: id });
  mockGraph(t, [
    { path: `${casesPath}/${genericCase.id}`, body: genericCase },
    { path, body: { value: [relation('901')], '@odata.nextLink': `https://graph.microsoft.com${path}?$skiptoken=next` } },
    { path, body: { value: [relation('902'), relation('901'), { '@odata.type': `#${namespace}.workspaceIndicatorRelation`, relatedResourceId: 'other' }] } },
  ]);
  const result = await invoke('ResolveCaseReference', { referenceType: 'case', referenceId: genericCase.id });
  assert.deepEqual(result.incidentIds, ['901', '902']);
  assert.equal(result.incidentId, undefined);
});

test('a missing incident Case resolves to an explicitly identified legacy incident, not a fabricated Case', async (t) => {
  mockGraph(t, [lookup({ value: [] }), { path: incidentPath, body: { id: '912751' } }]);
  const result = await invoke('ResolveCaseReference', { referenceType: 'incident', referenceId: '912751' });
  assert.equal(result.incidentId, '912751');
  assert.equal(result.caseId, undefined);
  assert.equal(result._mcp.source, 'incidents');
});

for (const raw of [undefined, 'unexpected non-JSON response body']) {
  test(`UpdateIncident accepts empty/asynchronous HTTP 202 (${String(raw)}) without a second write`, async (t) => {
    const requests = mockGraph(t, [
      lookup(),
      { path: statusesPath, body: statusTree },
      {
        path: `${casesPath}/${incidentCase.id}`,
        method: 'PATCH',
        status: 202,
        raw,
        check: (request) => assert.deepEqual(request.body, {
          '@odata.type': `#${namespace}.incidentCase`,
          status: 'Resolved',
          classification: 'truePositive',
          determination: 'malware',
        }),
      },
    ]);
    const result = await invoke('UpdateIncident', { incidentId: '912751', status: 'resolved', classification: 'truePositive', determination: 'malware' });
    assert.equal(result.result, 'ACCEPTED');
    assert.equal(result.httpStatus, 202);
    assert.equal(result.pendingSynchronization, true);
    assert.equal(result.id, '912751');
    assert.equal(result.caseId, incidentCase.id);
    assert.equal(result.status, undefined);
    assert.equal(requests.filter((request) => request.method === 'PATCH').length, 1);
  });
}

test('UpdateCase discovers and validates exact custom tenant statuses', async (t) => {
  mockGraph(t, [
    { path: `${casesPath}/${incidentCase.id}`, body: incidentCase },
    { path: statusesPath, body: statusTree },
    { path: `${casesPath}/${incidentCase.id}`, method: 'PATCH', status: 202, check: (request) => assert.equal(request.body.status, 'Closed - Fixed') },
  ]);
  const result = await invoke('UpdateCase', { caseId: incidentCase.id, status: 'Closed - Fixed' });
  assert.deepEqual(result.submittedChanges, { status: 'Closed - Fixed' });
  assert.equal(result.result, 'ACCEPTED');
});

test('a status not configured in the tenant stops before any write', async (t) => {
  mockGraph(t, [{ path: `${casesPath}/${incidentCase.id}`, body: incidentCase }, { path: statusesPath, body: statusTree }]);
  await assert.rejects(invoke('UpdateCase', { caseId: incidentCase.id, status: 'closed' }), /tenant displayName/);
});

test('legacy-only fields are sent as a single unchanged legacy PATCH', async (t) => {
  const fields = { status: 'resolved', severity: 'high', description: '', resolvingComment: 'Completed', customTags: [] };
  mockGraph(t, [{ path: incidentPath, method: 'PATCH', body: { id: '912751', ...fields }, check: (request) => assert.deepEqual(request.body, fields) }]);
  const result = await invoke('UpdateIncident', { incidentId: '912751', ...fields });
  assert.equal(result._mcp.fallback.reason, 'legacy-compatibility');
});

test('assignment clearing preserves the existing legacy null semantics', async (t) => {
  mockGraph(t, [{ path: incidentPath, method: 'PATCH', body: { id: '912751', assignedTo: null }, check: (request) => assert.deepEqual(request.body, { assignedTo: null }) }]);
  assert.equal((await invoke('UpdateIncident', { incidentId: '912751', assignedTo: null }))._mcp.source, 'incidents');
});

test('an unmappable legacy status is not invented from localized tenant labels', async (t) => {
  mockGraph(t, [
    lookup(),
    { path: statusesPath, body: { value: [{ displayName: 'Resolvido' }] } },
    { path: incidentPath, method: 'PATCH', body: { id: '912751', status: 'resolved' }, check: (request) => assert.deepEqual(request.body, { status: 'resolved' }) },
  ]);
  assert.equal((await invoke('UpdateIncident', { incidentId: '912751', status: 'resolved' }))._mcp.fallback.reason, 'legacy-compatibility');
});

test('a missing Case falls back to the original incident PATCH before any beta write', async (t) => {
  mockGraph(t, [lookup({ value: [] }), { path: incidentPath, method: 'PATCH', body: { id: '912751', severity: 'high' } }]);
  assert.equal((await invoke('UpdateIncident', { incidentId: '912751', severity: 'high' }))._mcp.fallback.reason, 'not-found');
});

test('a beta PATCH 404 falls back to the underlying Incident ID, not the Case ID', async (t) => {
  mockGraph(t, [
    { path: `${casesPath}/${incidentCase.id}`, body: incidentCase },
    { path: statusesPath, body: statusTree },
    { path: `${casesPath}/${incidentCase.id}`, method: 'PATCH', status: 404 },
    { path: incidentPath, method: 'PATCH', body: { id: '912751', status: 'resolved' }, check: (request) => assert.deepEqual(request.body, { status: 'resolved' }) },
  ]);
  assert.equal((await invoke('UpdateCase', { caseId: incidentCase.id, status: 'Resolved' }))._mcp.fallback.reason, 'http-404');
});

test('a custom Case status cannot be silently broadened to a legacy resolved status', async (t) => {
  mockGraph(t, [
    { path: `${casesPath}/${incidentCase.id}`, body: incidentCase },
    { path: statusesPath, body: statusTree },
    { path: `${casesPath}/${incidentCase.id}`, method: 'PATCH', status: 404 },
  ]);
  await assert.rejects(invoke('UpdateCase', { caseId: incidentCase.id, status: 'Closed - Fixed' }), /no fallback write was sent/);
});

test('tenant status configuration 404 can fall back after resolving the actual Incident ID', async (t) => {
  mockGraph(t, [
    { path: `${casesPath}/${incidentCase.id}`, body: incidentCase },
    { path: statusesPath, status: 404 },
    { path: incidentPath, method: 'PATCH', body: { id: '912751', status: 'resolved' }, check: (request) => assert.deepEqual(request.body, { status: 'resolved' }) },
  ]);
  assert.equal((await invoke('UpdateCase', { caseId: incidentCase.id, status: 'Resolved' }))._mcp.fallback.reason, 'http-404');
});

test('tenant status configuration 403 cannot be bypassed through a legacy write', async (t) => {
  mockGraph(t, [lookup(), { path: statusesPath, status: 403 }]);
  await assert.rejects(invoke('UpdateIncident', { incidentId: '912751', status: 'resolved' }), /HTTP 403/);
});

test('ambiguous tenant status displayNames preserve the explicit legacy operation without a beta mutation', async (t) => {
  mockGraph(t, [
    lookup(),
    { path: statusesPath, body: { value: [{ displayName: 'Resolved', customStatuses: [{ displayName: 'Resolved' }] }] } },
    { path: incidentPath, method: 'PATCH', body: { id: '912751', status: 'resolved' } },
  ]);
  assert.equal((await invoke('UpdateIncident', { incidentId: '912751', status: 'resolved' }))._mcp.fallback.reason, 'legacy-compatibility');
});

for (const status of [400, 401, 403, 429, 500, 503]) {
  test(`a beta PATCH HTTP ${status} is never repeated through the legacy API`, async (t) => {
    mockGraph(t, [lookup(), { path: `${casesPath}/${incidentCase.id}`, method: 'PATCH', status }]);
    await assert.rejects(invoke('UpdateIncident', { incidentId: '912751', severity: 'high' }), new RegExp(`HTTP ${status}`));
  });
}

test('unexpected successful PATCH responses cannot cause a second mutation', async (t) => {
  mockGraph(t, [lookup(), { path: `${casesPath}/${incidentCase.id}`, method: 'PATCH', body: { ...incidentCase, id: 'wrong-case' } }]);
  await assert.rejects(invoke('UpdateIncident', { incidentId: '912751', severity: 'high' }), /different resource/);
});

test('a successful 200 beta PATCH is validated and returned without another mutation', async (t) => {
  mockGraph(t, [lookup(), { path: `${casesPath}/${incidentCase.id}`, method: 'PATCH', body: { ...incidentCase, severity: 'high' } }]);
  const result = await invoke('UpdateIncident', { incidentId: '912751', severity: 'high' });
  assert.equal(result.severity, 'high');
  assert.equal(result.id, '912751');
  assert.equal(result._mcp.source, 'cases');
});

test('a network failure after submitting a beta write does not replay it through incidents', async (t) => {
  mockGraph(t, [lookup(), { path: `${casesPath}/${incidentCase.id}`, method: 'PATCH', error: new TypeError('fetch failed') }]);
  await assert.rejects(invoke('UpdateIncident', { incidentId: '912751', severity: 'high' }), /Network request failed/);
});

test('generic Cases can update their supported fields without inventing an incident association', async (t) => {
  mockGraph(t, [
    { path: `${casesPath}/${genericCase.id}`, body: genericCase },
    { path: `${casesPath}/${genericCase.id}`, method: 'PATCH', body: { ...genericCase, displayName: 'Updated work' } },
  ]);
  const result = await invoke('UpdateCase', { caseId: genericCase.id, displayName: 'Updated work' });
  assert.equal(result.displayName, 'Updated work');
  assert.equal(result._mcp.source, 'cases');
  assert.equal(result.incidentId, undefined);
});

test('generic Cases reject incident-specific fields without a write or legacy fallback', async (t) => {
  mockGraph(t, [{ path: `${casesPath}/${genericCase.id}`, body: genericCase }]);
  await assert.rejects(invoke('UpdateCase', { caseId: genericCase.id, severity: 'high' }), /Generic case updates support/);
});

test('generic Case PATCH 404 cannot mutate one of its unrelated incidents as fallback', async (t) => {
  mockGraph(t, [
    { path: `${casesPath}/${genericCase.id}`, body: genericCase },
    { path: `${casesPath}/${genericCase.id}`, method: 'PATCH', status: 404 },
  ]);
  await assert.rejects(invoke('UpdateCase', { caseId: genericCase.id, displayName: 'Updated work' }), /HTTP 404/);
});

test('an empty explicit Cases list remains a Cases result, not a fabricated legacy Case collection', async (t) => {
  mockGraph(t, [{ path: incidentCasesPath, body: { value: [] } }]);
  const result = await invoke('ListCases', { incidentId: '912751' });
  assert.deepEqual(result.value, []);
  assert.equal(result._mcp.source, 'cases');
});

test('malformed successful collection responses are surfaced instead of treated as no matches', async (t) => {
  mockGraph(t, [{ path: incidentCasesPath, body: { data: [] } }]);
  await assert.rejects(invoke('GetIncidentById', { incidentId: '912751' }), /without a value array/);
});

test('status lookup follows pagination and retains custom statuses', async (t) => {
  mockGraph(t, [
    { path: statusesPath, body: { value: [statusTree.value[0]], '@odata.nextLink': `https://graph.microsoft.com${statusesPath}?$skiptoken=next` } },
    { path: statusesPath, body: { value: [statusTree.value[1]] } },
  ]);
  const result = await invoke('ListCaseStatuses', {});
  assert.equal(result.value.length, 2);
  assert.equal(result.value[1].customStatuses[0].displayName, 'Closed - Fixed');
});

test('legacy-only mode preserves the exact original response and disables explicit Cases tools', async (t) => {
  setting(t, 'false');
  const legacy = { id: '912751', status: 'active' };
  mockGraph(t, [{ path: incidentPath, body: legacy }]);
  assert.deepEqual(await invoke('GetIncidentById', { incidentId: '912751' }), legacy);
  await assert.rejects(invoke('GetCaseById', { caseId: incidentCase.id }), /beta is disabled/);
});

test('invalid feature settings and missing tokens fail explicitly without downstream requests', async (t) => {
  mockGraph(t, []);
  await assert.rejects(invoke('GetIncidentById', { incidentId: '912751' }, ''), /No user token/);
  setting(t, 'invalid');
  await assert.rejects(invoke('GetIncidentById', { incidentId: '912751' }), /must be true or false/);
});

test('HTTP MCP exposes Cases, asynchronous acceptance, and explicit partial-result errors', async (t) => {
  const clientFetch = globalThis.fetch;
  mockGraph(t, [
    lookup(),
    { path: statusesPath, body: statusTree },
    { path: `${casesPath}/${incidentCase.id}`, method: 'PATCH', status: 202 },
    lookup(),
    { path: incidentPath, status: 404, body: { error: 'Alerts unavailable' } },
  ]);
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
  const health = await (await clientFetch(`${base}/health`)).json();
  assert.equal(health.tools, 14);
  assert.equal(health.incidentStrategy, 'cases-first');
  assert.equal(health.caseManagementPreview, true);

  async function rpc(name, args) {
    const response = await clientFetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer http-cases-token' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
    });
    assert.equal(response.status, 200);
    return response.json();
  }
  const accepted = await rpc('UpdateIncident', { incidentId: '912751', status: 'resolved' });
  assert.equal(accepted.result.isError, undefined);
  assert.equal(JSON.parse(accepted.result.content[0].text).result, 'ACCEPTED');
  const partial = await rpc('GetIncidentById', { incidentId: '912751', includeAlertsData: true });
  assert.equal(partial.result.isError, true);
  const error = JSON.parse(partial.result.content[0].text);
  assert.match(error.error, /Case found/);
  assert.equal(error.partialResult.caseId, incidentCase.id);
});
