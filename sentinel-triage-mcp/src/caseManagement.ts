import { graphGet, graphGetNextPage, graphPatch, graphPatchResponse, graphErrorDiagnostics, GraphHttpError } from './apiClient.js';
import type { UpdateProperty } from './updateValidation.js';

export const CASES_PATH = '/security/caseManagement/cases';
export const CASE_NAMESPACE = 'microsoft.graph.security.caseManagement';
export type CaseType = 'incidentCase' | 'genericCase';

interface CaseReference {
  caseId: string;
  caseType: CaseType;
  incidentId?: string;
  resource: Record<string, unknown>;
}

interface Collection extends Record<string, unknown> {
  value: unknown[];
}

class CaseNotFoundError extends Error {}
class LegacyCompatibilityError extends Error {}

export class CaseFallbackError extends Error {
  constructor(
    public readonly operation: string,
    public readonly reason: string,
    public readonly primaryError: Error,
    public readonly fallbackError: unknown,
  ) {
    const message = fallbackError instanceof Error ? fallbackError.message : String(fallbackError);
    super(`Cases path failed: ${primaryError.message}. Incident fallback failed: ${message}`, { cause: fallbackError });
    this.name = 'CaseFallbackError';
  }
}

export class CaseEnrichmentError extends Error {
  constructor(message: string, public readonly partialResult: Record<string, unknown>, cause: unknown) {
    super(message, { cause });
    this.name = 'CaseEnrichmentError';
  }
}

export const caseUpdateProperties: Record<string, UpdateProperty> = {
  assignedTo: { type: 'string', minLength: 1, description: 'Assigned analyst. Use UpdateIncident to clear an incident assignment with null' },
  classification: {
    type: 'string',
    enum: ['unknown', 'truePositive', 'falsePositive', 'informationalExpectedActivity'],
    description: 'Incident case classification; never inferred automatically',
  },
  determination: {
    type: 'string',
    enum: [
      'unknown', 'apt', 'malware', 'securityPersonnel', 'securityTesting', 'unwantedSoftware',
      'other', 'multiStagedAttack', 'compromisedAccount', 'phishing', 'maliciousUserActivity',
      'notMalicious', 'notEnoughDataToValidate', 'confirmedActivity', 'lineOfBusinessApplication',
    ],
    description: 'Incident case determination',
  },
  displayName: { type: 'string', minLength: 1, description: 'Case display name' },
  severity: { type: 'string', enum: ['unknown', 'informational', 'low', 'medium', 'high'], description: 'Incident case severity' },
  status: { type: 'string', minLength: 1, description: 'Exact tenant status displayName returned by ListCaseStatuses' },
};

export function caseManagementEnabled(): boolean {
  const setting = process.env.CASE_MANAGEMENT_ENABLED ?? 'true';
  if (setting !== 'true' && setting !== 'false') {
    throw new Error('CASE_MANAGEMENT_ENABLED must be true or false');
  }
  return setting === 'true';
}

export function requireCaseManagement(): void {
  if (!caseManagementEnabled()) {
    throw new Error('Case Management beta is disabled. Set CASE_MANAGEMENT_ENABLED=true to enable Cases tools');
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function requireRecord(value: unknown, context: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${context} must be an object`);
  }
  return value;
}

export function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value;
}

function numericIncidentId(value: unknown): string {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error('incidentId must be a safely represented non-negative integer; no rounded ID will be used');
    }
    value = String(value);
  }
  const id = requireString(value, 'incidentId');
  if (!/^\d+$/.test(id) || BigInt(id) > 9223372036854775807n) {
    throw new Error('Cases incidentId must be a non-negative Int64 identifier');
  }
  return BigInt(id).toString();
}

function caseReference(value: unknown, expectedType?: CaseType): CaseReference {
  const resource = requireRecord(value, 'Case response');
  const caseId = requireString(resource.id, 'Case response id');
  const type = resource['@odata.type'];
  const caseType = type === `#${CASE_NAMESPACE}.incidentCase` ? 'incidentCase'
    : type === `#${CASE_NAMESPACE}.genericCase` ? 'genericCase'
    : type === undefined ? expectedType : undefined;
  if (!caseType || (expectedType && expectedType !== caseType)) {
    throw new Error('Microsoft Graph returned an unexpected case type');
  }
  return {
    caseId,
    caseType,
    resource,
    ...(caseType === 'incidentCase' ? { incidentId: numericIncidentId(resource.incidentId) } : {}),
  };
}

function collection(value: unknown): Collection {
  const response = requireRecord(value, 'Graph collection response');
  if (!Array.isArray(response.value)) {
    throw new Error('Microsoft Graph returned a collection without a value array');
  }
  return { ...response, value: response.value };
}

async function collectPages(first: unknown, path: string, version: 'v1.0' | 'beta', limit?: number): Promise<unknown[]> {
  let page = collection(first);
  const values: unknown[] = [];
  const visited = new Set<string>();
  while (true) {
    values.push(...page.value);
    if (limit !== undefined && values.length >= limit) return values.slice(0, limit);
    const next = page['@odata.nextLink'];
    if (next === undefined) return values;
    const nextLink = requireString(next, '@odata.nextLink');
    if (visited.has(nextLink)) throw new Error('Microsoft Graph returned a repeated pagination URL');
    visited.add(nextLink);
    page = collection(await graphGetNextPage(nextLink, path, version));
  }
}

function metadata(resource: Record<string, unknown>, source: 'cases' | 'incidents', extra: Record<string, unknown> = {}) {
  return {
    ...resource,
    _mcp: { source, apiVersion: source === 'cases' ? 'beta' : 'v1.0', preview: source === 'cases', ...extra },
  };
}

async function withIncidentFallback(
  operation: string,
  primary: () => Promise<Record<string, unknown>>,
  legacy: () => Promise<unknown>,
): Promise<Record<string, unknown>> {
  if (!caseManagementEnabled()) return requireRecord(await legacy(), 'Incident response');
  let primaryError: Error;
  try {
    return metadata(await primary(), 'cases');
  } catch (error: unknown) {
    if (!(error instanceof CaseNotFoundError) && !(error instanceof LegacyCompatibilityError) &&
        !(error instanceof GraphHttpError && error.status === 404)) {
      throw error;
    }
    primaryError = error;
  }
  const reason = primaryError instanceof GraphHttpError ? 'http-404'
    : primaryError instanceof LegacyCompatibilityError ? 'legacy-compatibility' : 'not-found';
  console.warn(`Case Management fallback: ${operation} (${reason})`);
  try {
    return metadata(requireRecord(await legacy(), 'Incident response'), 'incidents', {
      fallback: { reason, primaryError: primaryError.message, diagnostics: graphErrorDiagnostics(primaryError) },
    });
  } catch (error: unknown) {
    throw new CaseFallbackError(operation, reason, primaryError, error);
  }
}

async function findIncidentCase(incidentId: string): Promise<CaseReference> {
  if (!/^\d+$/.test(incidentId) || BigInt(incidentId) > 9223372036854775807n) {
    throw new LegacyCompatibilityError('The incident identifier cannot be queried as a Cases Int64; preserving the legacy ID');
  }
  const id = numericIncidentId(incidentId);
  const path = `${CASES_PATH}/${CASE_NAMESPACE}.incidentCase`;
  const first = await graphGet(path, { '$filter': `incidentId eq ${id}`, '$top': '2' }, 'beta');
  const matches = await collectPages(first, path, 'beta', 2);
  if (matches.length === 0) throw new CaseNotFoundError(`No incidentCase found for incidentId ${id}`);
  if (matches.length !== 1) throw new Error(`Multiple incident cases match incidentId ${id}; specify a Case ID`);
  const reference = caseReference(matches[0], 'incidentCase');
  if (reference.incidentId !== id) throw new Error('Microsoft Graph returned a case for a different incidentId');
  return reference;
}

async function readCase(caseId: string): Promise<CaseReference> {
  const id = requireString(caseId, 'caseId');
  const reference = caseReference(await graphGet(`${CASES_PATH}/${encodeURIComponent(id)}`, undefined, 'beta'));
  if (reference.caseId !== id) throw new Error('Microsoft Graph returned a different Case ID');
  return reference;
}

function projectIncident(reference: CaseReference): Record<string, unknown> {
  if (!reference.incidentId) throw new Error('A generic case cannot be projected as a single incident');
  const result: Record<string, unknown> = {
    id: reference.incidentId,
    caseId: reference.caseId,
    caseType: reference.caseType,
    caseDetails: reference.resource,
  };
  for (const field of ['displayName', 'severity', 'assignedTo', 'classification', 'determination', 'createdDateTime', 'summary', 'incidentWebUrl']) {
    if (reference.resource[field] !== undefined) result[field] = reference.resource[field];
  }
  if (reference.resource.lastModifiedDateTime !== undefined) result.lastUpdateDateTime = reference.resource.lastModifiedDateTime;
  if (reference.resource.status !== undefined) {
    result.caseStatus = reference.resource.status;
    result.status = reference.resource.status;
  }
  return result;
}

async function enrichIncident(incident: Record<string, unknown>): Promise<Record<string, unknown>> {
  const id = requireString(incident.id, 'incident id');
  try {
    const expanded = requireRecord(await graphGet(`/security/incidents/${encodeURIComponent(id)}`, { '$expand': 'alerts' }), 'Expanded incident');
    if (!Array.isArray(expanded.alerts)) throw new Error('Expanded incident response is missing the alerts array');
    return { ...incident, alerts: expanded.alerts };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new CaseEnrichmentError(`Case found, but correlated alerts could not be retrieved: ${message}`, incident, error);
  }
}

export async function getIncidentWithCases(incidentId: string, includeAlertsData: boolean): Promise<Record<string, unknown>> {
  const id = requireString(incidentId, 'incidentId');
  const result = await withIncidentFallback(
    'GetIncidentById',
    async () => projectIncident(await findIncidentCase(id)),
    () => graphGet(`/security/incidents/${encodeURIComponent(id)}`, includeAlertsData ? { '$expand': 'alerts' } : undefined),
  );
  const source = requireRecord(result._mcp ?? {}, 'MCP metadata').source;
  return includeAlertsData && source === 'cases' ? enrichIncident(result) : result;
}

export async function getCaseById(caseId: string, includeAlertsData: boolean): Promise<Record<string, unknown>> {
  requireCaseManagement();
  const reference = await readCase(caseId);
  const result = metadata({
    ...reference.resource,
    caseId: reference.caseId,
    ...(reference.incidentId ? { incidentId: reference.incidentId } : {}),
  }, 'cases');
  if (!includeAlertsData) return result;
  if (!reference.incidentId) throw new Error('A generic case has no single incident; use ResolveCaseReference to inspect its links');
  const incident = await enrichIncident(projectIncident(reference));
  return { ...result, alerts: incident.alerts };
}

export async function resolveCaseReference(referenceType: 'case' | 'incident', referenceId: string): Promise<Record<string, unknown>> {
  const id = requireString(referenceId, 'referenceId');
  if (referenceType === 'incident') {
    return withIncidentFallback('ResolveCaseReference', async () => {
      const reference = await findIncidentCase(id);
      return { caseId: reference.caseId, caseType: reference.caseType, incidentId: reference.incidentId, case: reference.resource };
    }, async () => ({ incidentId: id, incident: await graphGet(`/security/incidents/${encodeURIComponent(id)}`) }));
  }
  requireCaseManagement();
  const reference = await readCase(id);
  if (reference.incidentId) {
    return metadata({ caseId: reference.caseId, caseType: reference.caseType, incidentId: reference.incidentId, case: reference.resource }, 'cases');
  }
  const path = `${CASES_PATH}/${encodeURIComponent(id)}/relations`;
  const relations = await collectPages(await graphGet(path, undefined, 'beta'), path, 'beta');
  const incidentIds = new Set<string>();
  for (const value of relations) {
    const relation = requireRecord(value, 'Case relation');
    if (relation['@odata.type'] === `#${CASE_NAMESPACE}.incidentRelation`) {
      incidentIds.add(requireString(relation.relatedResourceId, 'Related incident ID'));
    }
  }
  return metadata({ caseId: reference.caseId, caseType: reference.caseType, incidentIds: [...incidentIds], case: reference.resource, relations }, 'cases');
}

export async function listCaseStatuses(caseType: CaseType): Promise<Record<string, unknown>> {
  requireCaseManagement();
  const path = `/security/caseManagement/caseTypeConfigurations/${caseType}/statuses`;
  const values = await collectPages(await graphGet(path, undefined, 'beta'), path, 'beta');
  for (const value of values) {
    const status = requireRecord(value, 'Case status');
    requireString(status.displayName, 'Status displayName');
    if (status.customStatuses !== undefined && !Array.isArray(status.customStatuses)) {
      throw new Error('Case status customStatuses must be an array');
    }
    for (const custom of Array.isArray(status.customStatuses) ? status.customStatuses : []) {
      requireString(requireRecord(custom, 'Custom status').displayName, 'Custom status displayName');
    }
  }
  return metadata({ caseType, value: values }, 'cases');
}

function statusNames(tree: Record<string, unknown>, includeCustom: boolean): string[] {
  const names: string[] = [];
  for (const value of collection(tree).value) {
    const status = requireRecord(value, 'Case status');
    names.push(requireString(status.displayName, 'Status displayName'));
    if (includeCustom && Array.isArray(status.customStatuses)) {
      for (const custom of status.customStatuses) {
        names.push(requireString(requireRecord(custom, 'Custom status').displayName, 'Custom status displayName'));
      }
    }
  }
  return names;
}

async function legacyStatusDefinition(status: string): Promise<Record<string, unknown>> {
  const tree = await listCaseStatuses('incidentCase');
  const matches = collection(tree).value.map((value) => requireRecord(value, 'Case status'))
    .filter((value) => requireString(value.displayName, 'Status displayName').toLowerCase() === status);
  if (matches.length !== 1) {
    throw new LegacyCompatibilityError(`Legacy status ${status} has no unique matching top-level Cases status; preserving the legacy operation`);
  }
  const family = statusNames({ value: matches }, true);
  const allNames = statusNames(tree, true);
  if (family.some((name) => allNames.filter((candidate) => candidate === name).length !== 1)) {
    throw new LegacyCompatibilityError('Case status labels are ambiguous; preserving the legacy operation');
  }
  return matches[0];
}

async function legacyStatusName(status: string): Promise<string> {
  return requireString((await legacyStatusDefinition(status)).displayName, 'Status displayName');
}

function quote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function pageParameter(value: unknown, name: string, maximum?: number): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < (name === 'top' ? 1 : 0) ||
      (maximum !== undefined && value > maximum)) {
    throw new Error(`${name} must be an integer ${name === 'top' ? 'between 1 and 100' : 'greater than or equal to 0'}`);
  }
  return String(value);
}

function orderBy(value: unknown, legacy: boolean): string | undefined {
  if (value === undefined) return undefined;
  const expression = requireString(value, 'orderBy');
  const supported = ['id', 'displayName', 'createdDateTime', 'lastModifiedDateTime', 'assignedTo'];
  const clauses = expression.split(',').map((item) => {
    const match = /^\s*([A-Za-z]+)(?:\s+(asc|desc))?\s*$/.exec(item);
    const field = match?.[1] === 'lastUpdateDateTime' && legacy ? 'lastModifiedDateTime' : match?.[1];
    if (!field || !supported.includes(field)) {
      if (legacy) throw new LegacyCompatibilityError('The requested ordering is not supported by Cases');
      throw new Error('orderBy supports id, displayName, createdDateTime, lastModifiedDateTime and assignedTo');
    }
    return `${field}${match?.[2] ? ` ${match[2]}` : ''}`;
  });
  return clauses.join(', ');
}

async function caseListQuery(params: Record<string, unknown>, caseType: CaseType, legacy: boolean) {
  const filters: string[] = [];
  if (legacy && params.search) throw new LegacyCompatibilityError('Cases does not support the legacy free-text search query');
  if (legacy && typeof params.top === 'number' && params.top > 100) {
    throw new LegacyCompatibilityError('Cases limits top to 100; preserving the requested legacy page size');
  }
  const ordering = orderBy(params.orderBy, legacy);
  const top = pageParameter(params.top, 'top', 100);
  const skip = pageParameter(params.skip, 'skip');
  for (const [parameter, operator] of [['createdAfter', 'gt'], ['createdBefore', 'lt']]) {
    if (params[parameter] !== undefined) {
      const date = requireString(params[parameter], parameter);
      if (!/^\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})$/.test(date) || !Number.isFinite(Date.parse(date))) {
        throw new Error(`${parameter} must be an ISO 8601 timestamp with timezone`);
      }
      filters.push(`createdDateTime ${operator} ${date}`);
    }
  }
  for (const field of ['assignedTo', 'displayName', 'severity', 'classification', 'determination']) {
    if (params[field] !== undefined) {
      if (caseType === 'genericCase' && ['severity', 'classification', 'determination'].includes(field)) {
        throw new Error(`${field} is only supported for incidentCase`);
      }
      filters.push(`${field} eq ${quote(requireString(params[field], field))}`);
    }
  }
  if (params.status !== undefined) {
    const status = requireString(params.status, 'status');
    const names = legacy ? statusNames({ value: [await legacyStatusDefinition(status)] }, true) : [status];
    const expression = names.map((name) => `status eq ${quote(name)}`).join(' or ');
    filters.push(names.length > 1 ? `(${expression})` : expression);
  }
  if (params.incidentId !== undefined) {
    if (caseType !== 'incidentCase') throw new Error('incidentId is only supported for incidentCase');
    filters.push(`incidentId eq ${numericIncidentId(params.incidentId)}`);
  }
  return {
    '$filter': filters.length > 0 ? filters.join(' and ') : undefined,
    '$orderby': ordering,
    '$top': top,
    '$skip': skip,
  };
}

export async function listCases(params: Record<string, unknown>, caseType: CaseType): Promise<Record<string, unknown>> {
  requireCaseManagement();
  const path = `${CASES_PATH}/${CASE_NAMESPACE}.${caseType}`;
  const response = collection(await graphGet(path, await caseListQuery(params, caseType, false), 'beta'));
  for (const value of response.value) caseReference(value, caseType);
  return metadata(response, 'cases', { caseType });
}

export async function listIncidentsWithCases(
  params: Record<string, unknown>,
  legacyQuery: Record<string, string | undefined>,
): Promise<Record<string, unknown>> {
  const result = await withIncidentFallback('ListIncidents', async () => {
    const path = `${CASES_PATH}/${CASE_NAMESPACE}.incidentCase`;
    const response = collection(await graphGet(path, await caseListQuery(params, 'incidentCase', true), 'beta'));
    if (response.value.length === 0 && response['@odata.nextLink'] === undefined && (params.skip === undefined || params.skip === 0)) {
      throw new CaseNotFoundError('No incident cases matched the requested first page');
    }
    return { ...response, value: response.value.map((value) => projectIncident(caseReference(value, 'incidentCase'))) };
  }, () => graphGet('/security/incidents', legacyQuery));
  const source = requireRecord(result._mcp ?? {}, 'MCP metadata').source;
  if (params.includeAlertsData && source === 'cases') {
    const enriched: Record<string, unknown>[] = [];
    for (const value of collection(result).value) {
      enriched.push(await enrichIncident(requireRecord(value, 'Projected incident')));
    }
    return { ...result, value: enriched };
  }
  return result;
}

async function patchCase(reference: CaseReference, body: Record<string, unknown>, incidentProjection: boolean): Promise<Record<string, unknown>> {
  const payload = { '@odata.type': `#${CASE_NAMESPACE}.${reference.caseType}`, ...body };
  const response = await graphPatchResponse(`${CASES_PATH}/${encodeURIComponent(reference.caseId)}`, payload, 'beta');
  if (response.status === 202) {
    return {
      ...(incidentProjection && reference.incidentId ? { id: reference.incidentId } : {}),
      caseId: reference.caseId,
      ...(reference.incidentId ? { incidentId: reference.incidentId } : {}),
      result: 'ACCEPTED',
      httpStatus: 202,
      pendingSynchronization: true,
      submittedChanges: body,
      message: 'Case update accepted. Synchronized incident fields may take a few minutes to appear; no legacy write was repeated.',
    };
  }
  if (response.status !== 200) throw new Error(`Unexpected Cases update status ${response.status}; check the target before retrying`);
  const updated = caseReference(response.body, reference.caseType);
  if (updated.caseId !== reference.caseId || updated.incidentId !== reference.incidentId) {
    throw new Error('Cases update returned a different resource; check the target before retrying');
  }
  return incidentProjection ? projectIncident(updated) : { ...updated.resource, caseId: updated.caseId };
}

export async function updateIncidentWithCases(incidentId: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  return withIncidentFallback('UpdateIncident', async () => {
    const unsupported = Object.keys(body).filter((name) => !Object.hasOwn(caseUpdateProperties, name));
    if (unsupported.length > 0 || body.assignedTo === null) {
      throw new LegacyCompatibilityError(`Preserving the entire legacy update for unsupported Cases fields or assignment clearing: ${unsupported.join(', ') || 'assignedTo: null'}`);
    }
    const reference = await findIncidentCase(incidentId);
    const payload = { ...body };
    if (typeof body.status === 'string') payload.status = await legacyStatusName(body.status);
    return patchCase(reference, payload, true);
  }, () => graphPatch(`/security/incidents/${encodeURIComponent(incidentId)}`, body));
}

export async function updateCaseById(caseId: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  requireCaseManagement();
  const reference = await readCase(caseId);
  if (reference.caseType === 'genericCase' && Object.keys(body).some((name) => !['displayName', 'status', 'assignedTo'].includes(name))) {
    throw new Error('Generic case updates support displayName, status and assignedTo in this tool');
  }
  const primary = async () => {
    if (typeof body.status === 'string') {
      const names = statusNames(await listCaseStatuses(reference.caseType), true).filter((name) => name === body.status);
      if (names.length !== 1) throw new Error('status must uniquely match a tenant displayName returned by ListCaseStatuses');
    }
    return patchCase(reference, body, false);
  };
  const legacy = async () => {
    if (!reference.incidentId) throw new Error('A generic case has no /security/incidents fallback');
    const payload = { ...body };
    if (typeof body.status === 'string') {
      const status = body.status.toLowerCase();
      if (!['active', 'resolved', 'redirected'].includes(status)) {
        throw new Error('A custom Case status cannot be safely translated to a legacy incident status; no fallback write was sent');
      }
      payload.status = status;
    }
    return graphPatch(`/security/incidents/${encodeURIComponent(reference.incidentId)}`, payload);
  };
  if (reference.caseType === 'genericCase') return metadata(await primary(), 'cases');
  return withIncidentFallback('UpdateCase', primary, legacy);
}
