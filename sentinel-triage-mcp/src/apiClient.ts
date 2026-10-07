import { AsyncLocalStorage } from 'node:async_hooks';

const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';

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
): Promise<unknown> {
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
    throw new Error(`HTTP ${res.status} from ${url}: ${text}`);
  }

  return res.json();
}

function buildUrl(path: string, params?: Record<string, string | undefined>): string {
  const url = new URL(`${GRAPH_BASE}${path}`);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== '') {
        url.searchParams.set(key, value);
      }
    }
  }
  return url.toString();
}

export async function graphGet(path: string, params?: Record<string, string | undefined>): Promise<unknown> {
  return httpRequest(buildUrl(path, params), getUserToken());
}

export async function graphPost(path: string, body: unknown): Promise<unknown> {
  return httpRequest(buildUrl(path), getUserToken(), 'POST', body);
}

export async function graphPatch(path: string, body: unknown): Promise<unknown> {
  return httpRequest(buildUrl(path), getUserToken(), 'PATCH', body);
}
