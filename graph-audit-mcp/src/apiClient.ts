import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';

const GRAPH_ORIGIN = 'https://graph.microsoft.com';
const GRAPH_VERSION = 'v1.0';

export const userTokenStore = new AsyncLocalStorage<string | undefined>();

interface UpstreamContext {
  service: 'microsoft-graph';
  method: 'GET';
  url: string;
  clientRequestId: string;
  requestId?: string;
  date?: string;
  retryAfter?: string;
  errorCode?: string;
}

export class GraphHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly upstream: UpstreamContext,
  ) {
    super(`Microsoft Graph returned HTTP ${status}`);
    this.name = 'GraphHttpError';
  }
}

export class GraphRequestError extends Error {
  constructor(
    message: string,
    public readonly diagnostics: Record<string, unknown>,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'GraphRequestError';
  }
}

function object(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function getUserToken(): string {
  const token = userTokenStore.getStore();
  if (!token) {
    throw new GraphRequestError('Missing authentication. Send an Authorization: Bearer <token> header.', {
      code: 'AUTHENTICATION_REQUIRED',
      automaticRetryAllowed: false,
      guidance: ['Configure delegated OAuth token passthrough. This server does not store or acquire credentials.'],
    });
  }
  return token;
}

function safeErrorDetails(status: number): { automaticRetryAllowed: false; guidance: string[] } {
  if (status === 401 || status === 403) {
    return {
      automaticRetryAllowed: false,
      guidance: [
        'Verify the delegated Microsoft Graph permission, admin consent, OAuth connection, and the signed-in user role.',
        'Audit logs require AuditLog.Read.All; risky users require IdentityRiskyUser.Read.All.',
      ],
    };
  }
  if (status === 429) {
    return {
      automaticRetryAllowed: false,
      guidance: ['Respect Retry-After before manually retrying. Do not start an automatic retry loop.'],
    };
  }
  return {
    automaticRetryAllowed: false,
    guidance: ['Report the HTTP status and correlation identifiers, then retry only when it is safe to do so.'],
  };
}

export function graphErrorDiagnostics(error: unknown): Record<string, unknown> {
  if (error instanceof GraphRequestError) return error.diagnostics;
  if (error instanceof GraphHttpError) {
    return {
      code: 'UPSTREAM_HTTP_ERROR',
      httpStatus: error.status,
      upstream: error.upstream,
      ...safeErrorDetails(error.status),
    };
  }
  return { code: 'TOOL_ERROR', automaticRetryAllowed: false };
}

function parseErrorCode(text: string): { errorCode?: string; innerRequestId?: string; innerDate?: string } {
  try {
    const body = object(JSON.parse(text));
    const error = object(body.error);
    const inner = object(error.innerError ?? error.innererror);
    return {
      errorCode: typeof error.code === 'string' ? error.code : undefined,
      innerRequestId: typeof inner['request-id'] === 'string' ? inner['request-id'] : undefined,
      innerDate: typeof inner.date === 'string' ? inner.date : undefined,
    };
  } catch {
    return {};
  }
}

async function request(url: URL): Promise<Record<string, unknown>> {
  const token = getUserToken();
  const clientRequestId = randomUUID();
  let response: Response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        'client-request-id': clientRequestId,
        'return-client-request-id': 'true',
      },
    });
  } catch (error: unknown) {
    throw new GraphRequestError('Microsoft Graph network request failed', {
      code: 'UPSTREAM_NETWORK_ERROR',
      upstream: { service: 'microsoft-graph', method: 'GET', url: url.toString(), clientRequestId },
      automaticRetryAllowed: false,
      guidance: ['Check network reachability. No Graph response was received.'],
    }, { cause: error });
  }

  const baseContext: UpstreamContext = {
    service: 'microsoft-graph',
    method: 'GET',
    url: url.toString(),
    clientRequestId: response.headers.get('client-request-id') ?? clientRequestId,
    requestId: response.headers.get('request-id') ?? response.headers.get('x-ms-request-id') ?? undefined,
    date: response.headers.get('date') ?? undefined,
    retryAfter: response.headers.get('retry-after') ?? undefined,
  };
  let text: string;
  try {
    text = await response.text();
  } catch (error: unknown) {
    throw new GraphRequestError('Could not read the Microsoft Graph response', {
      code: 'UPSTREAM_RESPONSE_ERROR',
      httpStatus: response.status,
      upstream: baseContext,
      automaticRetryAllowed: false,
    }, { cause: error });
  }
  if (!response.ok) {
    const safeText = text.replaceAll(token, '[REDACTED]');
    const parsed = parseErrorCode(safeText);
    throw new GraphHttpError(response.status, {
      ...baseContext,
      requestId: baseContext.requestId ?? parsed.innerRequestId,
      date: baseContext.date ?? parsed.innerDate,
      errorCode: parsed.errorCode,
    });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error: unknown) {
    throw new GraphRequestError('Microsoft Graph returned invalid JSON', {
      code: 'INVALID_UPSTREAM_RESPONSE',
      httpStatus: response.status,
      upstream: baseContext,
      automaticRetryAllowed: false,
    }, { cause: error });
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new GraphRequestError('Microsoft Graph returned an unexpected response shape', {
      code: 'INVALID_UPSTREAM_RESPONSE',
      httpStatus: response.status,
      upstream: baseContext,
      automaticRetryAllowed: false,
    });
  }
  return parsed as Record<string, unknown>;
}

export async function graphGet(path: string, query?: Record<string, string | undefined>): Promise<Record<string, unknown>> {
  const url = new URL(`${GRAPH_ORIGIN}/${GRAPH_VERSION}${path}`);
  for (const [name, value] of Object.entries(query ?? {})) {
    if (value !== undefined) url.searchParams.set(name, value);
  }
  return request(url);
}

export function validateContinuationUrl(nextLink: string, expectedCollectionPath: string): URL {
  let url: URL;
  try {
    url = new URL(nextLink);
  } catch {
    throw new Error('Microsoft Graph returned an invalid continuation URL');
  }
  if (
    url.protocol !== 'https:' ||
    url.origin !== GRAPH_ORIGIN ||
    url.pathname !== `/${GRAPH_VERSION}${expectedCollectionPath}` ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== ''
  ) {
    throw new Error('Microsoft Graph returned an unexpected continuation URL; no token was forwarded');
  }
  return url;
}

export async function graphGetNextPage(
  nextLink: string,
  expectedCollectionPath: string,
): Promise<Record<string, unknown>> {
  return request(validateContinuationUrl(nextLink, expectedCollectionPath));
}

export interface PagedResult {
  value: unknown[];
  '@odata.nextLink'?: string;
  pagesFetched: number;
}

export async function graphGetPages(
  path: string,
  query: Record<string, string | undefined>,
  maxPages: number,
): Promise<PagedResult> {
  let page = await graphGet(path, query);
  validatePage(page);
  const value = [...page.value];
  let pagesFetched = 1;
  let nextLink = typeof page['@odata.nextLink'] === 'string' ? page['@odata.nextLink'] : undefined;

  while (nextLink && pagesFetched < maxPages) {
    page = await graphGetNextPage(nextLink, path);
    validatePage(page);
    value.push(...page.value);
    pagesFetched += 1;
    nextLink = typeof page['@odata.nextLink'] === 'string' ? page['@odata.nextLink'] : undefined;
  }

  return {
    value,
    ...(nextLink ? { '@odata.nextLink': nextLink } : {}),
    pagesFetched,
  };
}

function validatePage(page: Record<string, unknown>): asserts page is Record<string, unknown> & { value: unknown[] } {
  const nextLink = page['@odata.nextLink'];
  if (!Array.isArray(page.value) || (nextLink !== undefined && typeof nextLink !== 'string')) {
    throw new GraphRequestError('Microsoft Graph returned an invalid collection response', {
      code: 'INVALID_UPSTREAM_RESPONSE',
      automaticRetryAllowed: false,
      guidance: ['Do not interpret a malformed collection response as an empty result.'],
    });
  }
}
