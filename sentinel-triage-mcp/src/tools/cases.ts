import { registerTool } from '../toolRegistry.js';
import { buildUpdate } from '../updateValidation.js';
import {
  caseUpdateProperties, getCaseById, listCases, listCaseStatuses, requireRecord, requireString,
  resolveCaseReference, updateCaseById, type CaseType,
} from '../caseManagement.js';

function caseType(value: unknown): CaseType {
  if (value === undefined || value === 'incidentCase') return 'incidentCase';
  if (value === 'genericCase') return 'genericCase';
  throw new Error('caseType must be incidentCase or genericCase');
}

function argumentsObject(params: Record<string, unknown>, fields: string[]): Record<string, unknown> {
  const args = requireRecord(params, 'Tool arguments');
  for (const field of Object.keys(args)) {
    if (!fields.includes(field)) throw new Error(`Unsupported argument: ${field}`);
  }
  return args;
}

export function registerCaseTools(): void {
  const listProperties = {
    caseType: { type: 'string', enum: ['incidentCase', 'genericCase'], default: 'incidentCase', description: 'Case type to list' },
    incidentId: { type: 'string', pattern: '^\\d+$', description: 'Underlying incident ID, not a Case ID. Only for incidentCase' },
    createdAfter: { type: 'string', format: 'date-time', description: 'Cases created after this timestamp' },
    createdBefore: { type: 'string', format: 'date-time', description: 'Cases created before this timestamp' },
    assignedTo: { type: 'string', description: 'Assigned analyst' },
    displayName: { type: 'string', description: 'Exact case display name' },
    status: { type: 'string', description: 'Exact tenant status displayName from ListCaseStatuses' },
    severity: caseUpdateProperties.severity,
    classification: caseUpdateProperties.classification,
    determination: caseUpdateProperties.determination,
    orderBy: { type: 'string', description: 'Order by id, displayName, createdDateTime, lastModifiedDateTime or assignedTo' },
    top: { type: 'integer', minimum: 1, maximum: 100, description: 'Page size, maximum 100' },
    skip: { type: 'integer', minimum: 0, description: 'Items to skip' },
  };
  registerTool({
    name: 'ListCases',
    description: 'List Microsoft Graph beta incident or generic cases. Filter incidentCase by underlying incidentId to find its Case ID. Requires CaseManagement.Read.All. Use ListIncidents for Cases-first queries with legacy fallback',
    inputSchema: { type: 'object', properties: listProperties, additionalProperties: false },
    handler: async (params) => {
      const args = argumentsObject(params, Object.keys(listProperties));
      for (const field of ['severity', 'classification', 'determination']) {
        const property = caseUpdateProperties[field];
        if (args[field] !== undefined && (typeof args[field] !== 'string' || !property.enum?.includes(args[field]))) {
          throw new Error(`${field} must be one of: ${property.enum?.join(', ')}`);
        }
      }
      return listCases(args, caseType(args.caseType));
    },
  });
  registerTool({
    name: 'GetCaseById',
    description: 'Get a Microsoft Graph beta case using its Case ID, which is distinct from incidentId. Optionally enrich an incident case with alerts through the existing v1.0 incident API. Requires CaseManagement.Read.All',
    inputSchema: {
      type: 'object',
      properties: {
        caseId: { type: 'string', minLength: 1, description: 'Case resource ID, not the underlying incident ID' },
        includeAlertsData: { type: 'boolean', description: 'Include correlated alerts for an incidentCase; requires incident read access' },
      },
      required: ['caseId'],
      additionalProperties: false,
    },
    handler: async (params) => {
      const args = argumentsObject(params, ['caseId', 'includeAlertsData']);
      if (args.includeAlertsData !== undefined && typeof args.includeAlertsData !== 'boolean') {
        throw new Error('includeAlertsData must be a boolean');
      }
      return getCaseById(requireString(args.caseId, 'caseId'), args.includeAlertsData === true);
    },
  });
  registerTool({
    name: 'ResolveCaseReference',
    description: 'Resolve an explicitly identified Case ID or Incident ID without guessing or conflating them. Incident references use Cases first, with legacy fallback only on no match or 404. Generic cases can link multiple incidents',
    inputSchema: {
      type: 'object',
      properties: {
        referenceType: { type: 'string', enum: ['case', 'incident'], description: 'What kind of ID the user provided' },
        referenceId: { type: 'string', minLength: 1, description: 'The Case or Incident ID' },
      },
      required: ['referenceType', 'referenceId'],
      additionalProperties: false,
    },
    handler: async (params) => {
      const args = argumentsObject(params, ['referenceType', 'referenceId']);
      if (args.referenceType !== 'case' && args.referenceType !== 'incident') throw new Error('referenceType must be case or incident');
      return resolveCaseReference(args.referenceType, requireString(args.referenceId, 'referenceId'));
    },
  });
  registerTool({
    name: 'ListCaseStatuses',
    description: 'Read the tenant-defined status tree, including custom status displayNames, before updating or closing a Case. Requires CaseManagement.Read.All',
    inputSchema: {
      type: 'object',
      properties: { caseType: { type: 'string', enum: ['incidentCase', 'genericCase'], default: 'incidentCase' } },
      additionalProperties: false,
    },
    handler: async (params) => {
      const args = argumentsObject(params, ['caseType']);
      return listCaseStatuses(caseType(args.caseType));
    },
  });
  registerTool({
    name: 'UpdateCase',
    description: 'Update a verified Case ID using Microsoft Graph beta. No customTags/summary support; do not drop requested fields or reuse a Case ID as an Incident ID. Stop on 401/403 instead of trying other routes. Use status displayNames from ListCaseStatuses. ACCEPTED (202) is pending synchronization, never a reason to repeat a write. Requires CaseManagement.ReadWrite.All',
    inputSchema: {
      type: 'object',
      properties: { caseId: { type: 'string', minLength: 1 }, ...caseUpdateProperties },
      required: ['caseId'],
      minProperties: 2,
      additionalProperties: false,
    },
    handler: async (params) => {
      const { id, body } = buildUpdate(params, 'caseId', caseUpdateProperties);
      return updateCaseById(id, body);
    },
  });
}
