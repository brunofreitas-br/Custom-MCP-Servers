import { graphGet, graphGetPages } from './apiClient.js';
import { registerTool } from './toolRegistry.js';
import {
  combineFilters,
  equalsFilter,
  escapeODataString,
  optionalEnum,
  optionalInteger,
  optionalString,
  optionalTimestamp,
  requireId,
  validateArguments,
  validateTimeRange,
} from './validation.js';

const PAGE_SIZE_MAX = 1000;
const MAX_PAGES = 5;
const commonPageProperties = {
  pageSize: { type: 'integer', minimum: 1, maximum: PAGE_SIZE_MAX, default: 100, description: 'Items requested per Graph page.' },
  maxPages: { type: 'integer', minimum: 1, maximum: MAX_PAGES, default: 1, description: 'Maximum continuation pages to fetch, including the first page.' },
};
const timeProperties = {
  startDateTime: { type: 'string', format: 'date-time', description: 'Inclusive UTC lower bound, ending in Z.' },
  endDateTime: { type: 'string', format: 'date-time', description: 'Inclusive UTC upper bound, ending in Z.' },
};

function schema(properties: Record<string, unknown>, required: string[] = []): Record<string, unknown> {
  return { type: 'object', properties, required, additionalProperties: false };
}

function timeFilter(field: string, from: string | undefined, to: string | undefined): Array<string | undefined> {
  return [
    from ? `${field} ge ${from}` : undefined,
    to ? `${field} le ${to}` : undefined,
  ];
}

async function listSignIns(args: Record<string, unknown>): Promise<unknown> {
  const allowed = ['userId', 'appId', 'ipAddress', 'statusErrorCode', 'startDateTime', 'endDateTime', 'pageSize', 'maxPages'] as const;
  validateArguments(args, allowed);
  const userId = optionalString(args.userId, 'userId');
  const appId = optionalString(args.appId, 'appId');
  const ipAddress = optionalString(args.ipAddress, 'ipAddress', 64);
  const statusErrorCode = args.statusErrorCode === undefined
    ? undefined
    : optionalInteger(args.statusErrorCode, 'statusErrorCode', 0, 2147483647, 0);
  const from = optionalTimestamp(args.startDateTime, 'startDateTime');
  const to = optionalTimestamp(args.endDateTime, 'endDateTime');
  validateTimeRange(from, to);
  const pageSize = optionalInteger(args.pageSize, 'pageSize', 1, PAGE_SIZE_MAX, 100);
  const maxPages = optionalInteger(args.maxPages, 'maxPages', 1, MAX_PAGES, 1);
  const filter = combineFilters([
    equalsFilter('userId', userId),
    equalsFilter('appId', appId),
    equalsFilter('ipAddress', ipAddress),
    statusErrorCode === undefined ? undefined : `status/errorCode eq ${statusErrorCode}`,
    ...timeFilter('createdDateTime', from, to),
  ]);
  return graphGetPages('/auditLogs/signIns', { '$filter': filter, '$top': String(pageSize) }, maxPages);
}

async function listDirectoryAudits(args: Record<string, unknown>): Promise<unknown> {
  const allowed = ['activityDisplayName', 'category', 'result', 'initiatedByUserId', 'targetResourceId', 'startDateTime', 'endDateTime', 'pageSize', 'maxPages'] as const;
  validateArguments(args, allowed);
  const category = optionalEnum(args.category, 'category', [
    'ApplicationManagement', 'Authentication', 'Authorization', 'Device', 'DirectoryManagement',
    'EntitlementManagement', 'GroupManagement', 'Other', 'Policy', 'ResourceManagement',
    'RoleManagement', 'UserManagement',
  ] as const);
  const result = optionalEnum(args.result, 'result', ['success', 'failure', 'timeout', 'unknownFutureValue'] as const);
  const from = optionalTimestamp(args.startDateTime, 'startDateTime');
  const to = optionalTimestamp(args.endDateTime, 'endDateTime');
  validateTimeRange(from, to);
  const filter = combineFilters([
    equalsFilter('activityDisplayName', optionalString(args.activityDisplayName, 'activityDisplayName')),
    equalsFilter('category', category),
    equalsFilter('result', result),
    equalsFilter('initiatedBy/user/id', optionalString(args.initiatedByUserId, 'initiatedByUserId')),
    (() => {
      const targetResourceId = optionalString(args.targetResourceId, 'targetResourceId');
      return targetResourceId === undefined
        ? undefined
        : `targetResources/any(target: target/id eq '${escapeODataString(targetResourceId)}')`;
    })(),
    ...timeFilter('activityDateTime', from, to),
  ]);
  const pageSize = optionalInteger(args.pageSize, 'pageSize', 1, PAGE_SIZE_MAX, 100);
  const maxPages = optionalInteger(args.maxPages, 'maxPages', 1, MAX_PAGES, 1);
  return graphGetPages('/auditLogs/directoryAudits', { '$filter': filter, '$top': String(pageSize) }, maxPages);
}

async function listRiskyUsers(args: Record<string, unknown>): Promise<unknown> {
  const allowed = ['riskLevel', 'riskState', 'riskDetail', 'userId', 'pageSize', 'maxPages'] as const;
  validateArguments(args, allowed);
  const riskLevel = optionalEnum(args.riskLevel, 'riskLevel', ['low', 'medium', 'high', 'hidden', 'none', 'unknownFutureValue'] as const);
  const riskState = optionalEnum(args.riskState, 'riskState', ['none', 'confirmedSafe', 'remediated', 'dismissed', 'atRisk', 'confirmedCompromised', 'unknownFutureValue'] as const);
  const riskDetail = optionalEnum(args.riskDetail, 'riskDetail', [
    'none', 'adminGeneratedTemporaryPassword', 'userPerformedSecuredPasswordChange',
    'userPerformedSecuredPasswordReset', 'adminConfirmedSigninSafe', 'aiConfirmedSigninSafe',
    'userPassedMFADrivenByRiskBasedPolicy', 'adminDismissedAllRiskForUser',
    'adminConfirmedSigninCompromised', 'hidden', 'adminConfirmedUserCompromised',
    'unknownFutureValue',
  ] as const);
  const filter = combineFilters([
    equalsFilter('riskLevel', riskLevel),
    equalsFilter('riskState', riskState),
    equalsFilter('riskDetail', riskDetail),
    equalsFilter('id', optionalString(args.userId, 'userId')),
  ]);
  const pageSize = optionalInteger(args.pageSize, 'pageSize', 1, PAGE_SIZE_MAX, 100);
  const maxPages = optionalInteger(args.maxPages, 'maxPages', 1, MAX_PAGES, 1);
  return graphGetPages('/identityProtection/riskyUsers', { '$filter': filter, '$top': String(pageSize) }, maxPages);
}

function registerGetTool(name: string, description: string, path: string): void {
  registerTool({
    name,
    description,
    inputSchema: schema({ id: { type: 'string', minLength: 1, maxLength: 256, description: 'Exact Microsoft Graph resource ID.' } }, ['id']),
    handler: async (args) => {
      validateArguments(args, ['id']);
      return graphGet(`${path}/${encodeURIComponent(requireId(args.id))}`);
    },
  });
}

registerTool({
  name: 'ListSignIns',
  description: 'List Microsoft Entra sign-in records using validated, allowlisted filters.',
  inputSchema: schema({
    userId: { type: 'string' },
    appId: { type: 'string' },
    ipAddress: { type: 'string' },
    statusErrorCode: { type: 'integer', minimum: 0 },
    ...timeProperties,
    ...commonPageProperties,
  }),
  handler: listSignIns,
});
registerGetTool('GetSignInById', 'Get one Microsoft Entra sign-in record by its exact ID.', '/auditLogs/signIns');

registerTool({
  name: 'ListDirectoryAudits',
  description: 'List Microsoft Entra directory audit records using validated, allowlisted filters.',
  inputSchema: schema({
    activityDisplayName: { type: 'string' },
    category: { type: 'string', enum: ['ApplicationManagement', 'Authentication', 'Authorization', 'Device', 'DirectoryManagement', 'EntitlementManagement', 'GroupManagement', 'Other', 'Policy', 'ResourceManagement', 'RoleManagement', 'UserManagement'] },
    result: { type: 'string', enum: ['success', 'failure', 'timeout', 'unknownFutureValue'] },
    initiatedByUserId: { type: 'string' },
    targetResourceId: { type: 'string' },
    ...timeProperties,
    ...commonPageProperties,
  }),
  handler: listDirectoryAudits,
});
registerGetTool('GetDirectoryAuditById', 'Get one Microsoft Entra directory audit record by its exact ID.', '/auditLogs/directoryAudits');

registerTool({
  name: 'ListRiskyUsers',
  description: 'List Microsoft Entra ID Protection risky users using validated, allowlisted filters.',
  inputSchema: schema({
    riskLevel: { type: 'string', enum: ['low', 'medium', 'high', 'hidden', 'none', 'unknownFutureValue'] },
    riskState: { type: 'string', enum: ['none', 'confirmedSafe', 'remediated', 'dismissed', 'atRisk', 'confirmedCompromised', 'unknownFutureValue'] },
    riskDetail: { type: 'string', enum: ['none', 'adminGeneratedTemporaryPassword', 'userPerformedSecuredPasswordChange', 'userPerformedSecuredPasswordReset', 'adminConfirmedSigninSafe', 'aiConfirmedSigninSafe', 'userPassedMFADrivenByRiskBasedPolicy', 'adminDismissedAllRiskForUser', 'adminConfirmedSigninCompromised', 'hidden', 'adminConfirmedUserCompromised', 'unknownFutureValue'] },
    userId: { type: 'string' },
    ...commonPageProperties,
  }),
  handler: listRiskyUsers,
});
registerGetTool('GetRiskyUserById', 'Get one Microsoft Entra ID Protection risky user by exact ID.', '/identityProtection/riskyUsers');
