import { AsyncLocalStorage } from 'node:async_hooks';

const GRAPH_ORIGIN = 'https://graph.microsoft.com';
export type GraphVersion = 'v1.0' | 'beta';

export class GraphHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    public readonly responseText: string,
  ) {
    super(`HTTP ${status} from ${url}: ${responseText}`);
    this.name = 'GraphHttpError';
  }
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
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new GraphHttpError(res.status, url, text);
  }

  if (res.status === 202 || res.status === 204) return { status: res.status };
  const text = await res.text();
  return { status: res.status, body: text.length > 0 ? JSON.parse(text) : undefined };
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
