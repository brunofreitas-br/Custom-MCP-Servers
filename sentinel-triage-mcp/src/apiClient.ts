import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';

const GRAPH_ORIGIN = 'https://graph.microsoft.com';
export type GraphVersion = 'v1.0' | 'beta';

export class GraphHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    public readonly responseText: string,
    public readonly request: Record<string, unknown> = {},
  ) {
    super(`HTTP ${status} from ${url}: ${responseText}`);
    this.name = 'GraphHttpError';
  }
}

export class GraphRequestError extends Error {
  constructor(message: string, public readonly diagnostics: Record<string, unknown>, options?: ErrorOptions) {
    super(message, options);
    this.name = 'GraphRequestError';
  }
}

function object(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? { ...value } : {};
}

function parseErrorBody(text: string): Record<string, unknown> {
  try {
    return object(object(JSON.parse(text)).error);
  } catch (error: unknown) {
    if (!(error instanceof SyntaxError)) throw error;
    return {};
  }
}

export function graphErrorDiagnostics(error: unknown): Record<string, unknown> {
  if (error instanceof GraphRequestError) return error.diagnostics;
  if (!(error instanceof GraphHttpError)) {
    return { code: 'TOOL_ERROR', automaticRetryAllowed: false };
  }
  const status = error.status;
  const guidance = status === 401 || status === 403
    ? [
      'Stop this operation. Verify Graph delegated scopes, admin consent, the renewed connection and user/resource RBAC.',
      'Do not change IDs, fields or APIs to bypass authorization. A 403 alone does not prove which permission is missing.',
    ]
    : status === 404
      ? [
        'The requested resource was not available through this endpoint for this connection. Do not infer deletion, lack of permission, or a provider allowlist.',
        'Compare the exact Case/Incident IDs, tenant, connection and request IDs. A Case ID must never be reused as an Incident ID without a verified mapping.',
      ]
      : status === 429
        ? ['Respect Retry-After. Do not enter a retry loop or automatically repeat a write.']
        : ['Report the failure with its request identifiers. Check the target state before retrying a write.'];
  return {
    code: 'UPSTREAM_HTTP_ERROR',
    httpStatus: status,
    upstream: { service: 'graph', url: error.url, ...error.request },
    automaticRetryAllowed: false,
    guidance,
  };
}

export interface GraphResponse {
  status: number;
  body?: unknown;
}

// ── Per-request user token context ───────────────────────────────
// The server middleware stores the incoming user Bearer token here
// so that all downstream API calls forward it directly to Microsoft Graph.
// No server-side credentials needed — pure token passthrough.
export const userTokenStore = new AsyncLocalStorage<string | undefined>();

function getUserToken(): string {
  const token = userTokenStore.getStore();
  if (!token) {
    throw new Error(
      'No user token found. Ensure the client sends an Authorization: Bearer <token> header. ' +
      'This MCP server operates in token passthrough mode — it does not hold any credentials.',
    );
  }
  return token;
}

// ── HTTP helpers ─────────────────────────────────────────────────

async function httpRequest(
  url: string,
  token: string,
  method: 'GET' | 'POST' | 'PATCH' = 'GET',
  body?: unknown,
): Promise<GraphResponse> {
  const clientRequestId = randomUUID();
  const upstream = { service: 'graph', url, method, clientRequestId };
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'client-request-id': clientRequestId,
        'return-client-request-id': 'true',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (error: unknown) {
    throw new GraphRequestError(`Network request failed: ${method} ${url}`, {
      code: 'UPSTREAM_NETWORK_ERROR',
      upstream,
      automaticRetryAllowed: false,
      guidance: ['No successful response was received. Report this failure; check the target state before retrying a write.'],
    }, { cause: error });
  }
  const context = {
    ...upstream,
    requestId: res.headers.get('request-id') ?? res.headers.get('x-ms-request-id') ?? undefined,
    clientRequestId: res.headers.get('client-request-id') ?? clientRequestId,
    date: res.headers.get('date') ?? undefined,
    retryAfter: res.headers.get('retry-after') ?? undefined,
  };
  if (res.ok && (res.status === 202 || res.status === 204)) return { status: res.status };

  let text: string;
  try {
    text = await res.text();
  } catch (error: unknown) {
    throw new GraphRequestError(`Could not read Graph response: ${method} ${url}`, {
      code: 'UPSTREAM_RESPONSE_ERROR', httpStatus: res.status, upstream: context, automaticRetryAllowed: false,
      guidance: ['The response could not be read. Do not replay a write without checking whether it was applied.'],
    }, { cause: error });
  }
  if (!res.ok) {
    const safeText = text.replaceAll(token, '[REDACTED]');
    const errorBody = parseErrorBody(safeText);
    const inner = object(errorBody.innerError ?? errorBody.innererror);
    throw new GraphHttpError(res.status, url, safeText.slice(0, 4000), {
      ...context,
      requestId: context.requestId ?? inner['request-id'],
      date: context.date ?? inner.date,
      errorCode: typeof errorBody.code === 'string' ? errorBody.code : undefined,
    });
  }

  if (!text) return { status: res.status };
  try {
    return { status: res.status, body: JSON.parse(text) };
  } catch (error: unknown) {
    if (!(error instanceof SyntaxError)) throw error;
    throw new GraphRequestError(`Graph returned invalid JSON: ${method} ${url}`, {
      code: 'INVALID_UPSTREAM_RESPONSE', httpStatus: res.status, upstream: context, automaticRetryAllowed: false,
      guidance: ['Do not interpret a malformed response as no matches, and do not replay a write automatically.'],
    }, { cause: error });
  }
}

function buildUrl(path: string, params: Record<string, string | undefined> | undefined, version: GraphVersion): string {
  const url = new URL(`${GRAPH_ORIGIN}/${version}${path}`);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== '') {
        url.searchParams.set(key, value);
      }
    }
  }
  return url.toString();
}

function requireBody(response: GraphResponse): unknown {
  if (response.body === undefined) {
    throw new Error(`Microsoft Graph returned HTTP ${response.status} without the expected JSON body`);
  }
  return response.body;
}

export async function graphGet(
  path: string,
  params?: Record<string, string | undefined>,
  version: GraphVersion = 'v1.0',
): Promise<unknown> {
  return requireBody(await httpRequest(buildUrl(path, params, version), getUserToken()));
}

export async function graphGetNextPage(nextLink: string, expectedPath: string, version: GraphVersion): Promise<unknown> {
  if (!URL.canParse(nextLink)) throw new Error('Microsoft Graph returned an invalid pagination URL');
  const url = new URL(nextLink);
  if (url.origin !== GRAPH_ORIGIN || url.pathname !== `/${version}${expectedPath}` || url.username || url.password) {
    throw new Error('Microsoft Graph returned an unexpected pagination URL; no token was forwarded');
  }
  return requireBody(await httpRequest(url.toString(), getUserToken()));
}

export async function graphPost(path: string, body: unknown): Promise<unknown> {
  return requireBody(await httpRequest(buildUrl(path, undefined, 'v1.0'), getUserToken(), 'POST', body));
}

export async function graphPatch(path: string, body: unknown): Promise<unknown> {
  return requireBody(await graphPatchResponse(path, body));
}

export async function graphPatchResponse(
  path: string,
  body: unknown,
  version: GraphVersion = 'v1.0',
): Promise<GraphResponse> {
  return httpRequest(buildUrl(path, undefined, version), getUserToken(), 'PATCH', body);
}
