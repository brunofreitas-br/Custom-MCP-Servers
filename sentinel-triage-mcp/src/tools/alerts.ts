import { registerTool } from '../toolRegistry.js';
import { graphGet, graphPatch } from '../apiClient.js';
import { buildUpdate, commonUpdateProperties, type UpdateProperty } from '../updateValidation.js';

const alertUpdateProperties: Record<string, UpdateProperty> = {
  ...commonUpdateProperties,
  status: {
    type: 'string',
    enum: ['new', 'inProgress', 'resolved'],
    description: 'Set to resolved to close the alert, or inProgress to resume investigation',
  },
  customDetails: {
    type: 'object',
    additionalProperties: { type: 'string' },
    description: 'User-defined custom fields with string values',
  },
};

export function registerAlertTools() {
  registerTool({
    name: 'ListAlerts',
    description: 'List security alerts, sort them, and filter by date range, severity, and status',
    inputSchema: {
      type: 'object',
      properties: {
        createdAfter: { type: 'string', description: 'ISO 8601 timestamp — alerts created after this time' },
        createdBefore: { type: 'string', description: 'ISO 8601 timestamp — alerts created before this time' },
        severity: { type: 'string', enum: ['informational', 'low', 'medium', 'high'], description: 'Severity filter' },
        status: { type: 'string', enum: ['unknown', 'new', 'inProgress', 'resolved'], description: 'Current status filter' },
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

      const queryParams: Record<string, string | undefined> = {};
      if (filters.length > 0) queryParams['$filter'] = filters.join(' and ');
      if (params.top !== undefined) queryParams['$top'] = String(params.top);
      if (params.skip !== undefined) queryParams['$skip'] = String(params.skip);

      return graphGet('/security/alerts_v2', queryParams);
    },
  });

  registerTool({
    name: 'GetAlertById',
    description: 'Retrieve a security alert by ID with complete details including severity, status, classification, and related evidence',
    inputSchema: {
      type: 'object',
      properties: {
        alertId: { type: 'string', description: 'Unique identifier of the alert' },
      },
      required: ['alertId'],
    },
    handler: async (params) => {
      return graphGet(`/security/alerts_v2/${encodeURIComponent(params.alertId as string)}`);
    },
  });

  registerTool({
    name: 'UpdateAlert',
    description: 'Update a security alert, including closing it with status resolved. Only supplied fields are sent to Microsoft Graph; classification and determination are never inferred. Requires SecurityAlert.ReadWrite.All',
    inputSchema: {
      type: 'object',
      properties: {
        alertId: { type: 'string', minLength: 1, description: 'Unique identifier of the alert' },
        ...alertUpdateProperties,
      },
      required: ['alertId'],
      minProperties: 2,
      additionalProperties: false,
    },
    handler: async (params) => {
      const { id, body } = buildUpdate(params, 'alertId', alertUpdateProperties);
      return graphPatch(`/security/alerts_v2/${encodeURIComponent(id)}`, body);
    },
  });
}
