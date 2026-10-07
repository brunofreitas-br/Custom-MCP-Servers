import { registerTool } from '../toolRegistry.js';
import { graphGet, graphPatch } from '../apiClient.js';
import { buildUpdate, commonUpdateProperties, type UpdateProperty } from '../updateValidation.js';

const incidentUpdateProperties: Record<string, UpdateProperty> = {
  ...commonUpdateProperties,
  status: {
    type: 'string',
    enum: ['active', 'resolved', 'redirected'],
    description: 'Set to resolved to close the incident, or active to reopen it',
  },
  severity: {
    type: 'string',
    enum: ['unknown', 'informational', 'low', 'medium', 'high'],
    description: 'Incident severity',
  },
  displayName: { type: 'string', minLength: 1, description: 'Incident name' },
  description: { type: 'string', description: 'Incident description' },
  summary: { type: 'string', description: 'Overview of the attack' },
  resolvingComment: { type: 'string', description: 'Explanation of the resolution and classification choice' },
  customTags: {
    type: 'array',
    items: { type: 'string', minLength: 1 },
    description: 'Custom tags to set. An empty array clears the tags',
  },
};

export function registerIncidentTools() {
  registerTool({
    name: 'ListIncidents',
    description: 'List security incidents and filter by date range, severity, status, assigned analyst, and investigation state',
    inputSchema: {
      type: 'object',
      properties: {
        createdAfter: { type: 'string', description: 'ISO 8601 timestamp — return incidents created after this time' },
        createdBefore: { type: 'string', description: 'ISO 8601 timestamp — return incidents created before this time' },
        severity: { type: 'string', enum: ['informational', 'low', 'medium', 'high'], description: 'Severity filter' },
        status: { type: 'string', enum: ['active', 'resolved', 'redirected'], description: 'Current status filter' },
        assignedTo: { type: 'string', description: 'Filter by assigned analyst email' },
        classification: { type: 'string', enum: ['unknown', 'truePositive', 'falsePositive', 'informationalExpectedActivity'], description: 'Classification filter' },
        determination: { type: 'string', description: 'Determination filter (e.g., malware, phishing, multiStagedAttack)' },
        orderBy: { type: 'string', description: 'OData $orderby expression (e.g., createdDateTime desc)' },
        search: { type: 'string', description: 'Free-text search across incident data' },
        includeAlertsData: { type: 'boolean', description: 'Include correlated alerts in the response' },
        skip: { type: 'number', description: 'Number of items to skip for pagination' },
        top: { type: 'number', description: 'Maximum number of items to return' },
      },
    },
    handler: async (params) => {
      const filters: string[] = [];
      if (params.createdAfter) filters.push(`createdDateTime gt ${params.createdAfter}`);
      if (params.createdBefore) filters.push(`createdDateTime lt ${params.createdBefore}`);
      if (params.severity) filters.push(`severity eq '${params.severity}'`);
      if (params.status) filters.push(`status eq '${params.status}'`);
      if (params.assignedTo) filters.push(`assignedTo eq '${params.assignedTo}'`);
      if (params.classification) filters.push(`classification eq '${params.classification}'`);
      if (params.determination) filters.push(`determination eq '${params.determination}'`);

      const queryParams: Record<string, string | undefined> = {};
      if (filters.length > 0) queryParams['$filter'] = filters.join(' and ');
      if (params.orderBy) queryParams['$orderby'] = params.orderBy as string;
      if (params.top !== undefined) queryParams['$top'] = String(params.top);
      if (params.skip !== undefined) queryParams['$skip'] = String(params.skip);
      if (params.includeAlertsData) queryParams['$expand'] = 'alerts';
      if (params.search) queryParams['$search'] = `"${params.search}"`;

      return graphGet('/security/incidents', queryParams);
    },
  });

  registerTool({
    name: 'GetIncidentById',
    description: 'Retrieve a security incident by ID, including properties, correlated alerts, and metadata',
    inputSchema: {
      type: 'object',
      properties: {
        incidentId: { type: 'string', description: 'Unique identifier of the incident' },
        includeAlertsData: { type: 'boolean', description: 'Include correlated alerts data' },
      },
      required: ['incidentId'],
    },
    handler: async (params) => {
      const queryParams: Record<string, string | undefined> = {};
      if (params.includeAlertsData) queryParams['$expand'] = 'alerts';
      return graphGet(`/security/incidents/${encodeURIComponent(params.incidentId as string)}`, queryParams);
    },
  });

  registerTool({
    name: 'UpdateIncident',
    description: 'Update a security incident, including closing it with status resolved. Only supplied fields are sent to Microsoft Graph; classification and determination are never inferred. Requires SecurityIncident.ReadWrite.All',
    inputSchema: {
      type: 'object',
      properties: {
        incidentId: { type: 'string', minLength: 1, description: 'Unique identifier of the incident' },
        ...incidentUpdateProperties,
      },
      required: ['incidentId'],
      minProperties: 2,
      additionalProperties: false,
    },
    handler: async (params) => {
      const { id, body } = buildUpdate(params, 'incidentId', incidentUpdateProperties);
      return graphPatch(`/security/incidents/${encodeURIComponent(id)}`, body);
    },
  });
}
