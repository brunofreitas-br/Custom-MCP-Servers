import type { Request } from "express";
import { randomUUID } from "node:crypto";

const GRAPH_BASE = "https://graph.microsoft.com/v1.0";
const DEFENDER_BASE = "https://api.securitycenter.microsoft.com/api";

export interface ApiRequestOptions {
  base: "graph" | "defender";
  method: string;
  path: string;
  body?: Record<string, unknown> | null;
  token: string;
  params?: Record<string, string>;
}

export class ApiRequestError extends Error {
  constructor(message: string, public readonly diagnostics: Record<string, unknown>, options?: ErrorOptions) {
    super(message, options);
    this.name = "ApiRequestError";
  }
}

function object(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? { ...value } : {};
}

function errorBody(text: string): Record<string, unknown> {
  try {
    return object(object(JSON.parse(text)).error);
  } catch (error: unknown) {
    if (!(error instanceof SyntaxError)) throw error;
    return {};
  }
}

function guidance(status: number | undefined, method: string): string[] {
  if (status === 401 || status === 403) {
    return [
      "Stop this operation. Verify the connection's token audience, delegated permissions, consent and user/device-group RBAC.",
      "Do not change targets or use another API to bypass the authorization failure. A 403 alone does not identify a missing permission.",
    ];
  }
  if (status === 404) return ["The requested resource was not available through this endpoint. Verify the exact MDE machine/action ID, tenant and connection; do not infer deletion or reuse an Entra/Case ID."];
  if (status === 429) return ["Respect Retry-After. Do not repeatedly resubmit a device action."];
  return [method === "GET"
    ? "Report the failed read and its request identifiers; do not treat it as an empty result."
    : "The action outcome is not confirmed. Check Defender Action center before retrying; do not automatically replay a write."];
}

async function request(url: string, opts: ApiRequestOptions): Promise<unknown> {
  const clientRequestId = randomUUID();
  const upstream = { service: opts.base, method: opts.method, url, clientRequestId };

  const headers: Record<string, string> = {
    Authorization: `Bearer ${opts.token}`,
    "Content-Type": "application/json",
    "client-request-id": clientRequestId,
    "return-client-request-id": "true",
  };

  const fetchOpts: RequestInit = { method: opts.method, headers };
  if (opts.body) {
    fetchOpts.body = JSON.stringify(opts.body);
  }

  let response: globalThis.Response;
  try {
    response = await fetch(url, fetchOpts);
  } catch (error: unknown) {
    throw new ApiRequestError(`Network request failed: ${opts.method} ${url}`, {
      code: "UPSTREAM_NETWORK_ERROR", upstream, automaticRetryAllowed: false, guidance: guidance(undefined, opts.method),
    }, { cause: error });
  }
  const context = {
    ...upstream,
    requestId: response.headers.get("request-id") ?? response.headers.get("x-ms-request-id") ?? undefined,
    clientRequestId: response.headers.get("client-request-id") ?? clientRequestId,
    date: response.headers.get("date") ?? undefined,
    retryAfter: response.headers.get("retry-after") ?? undefined,
  };
  let responseText: string;
  try {
    responseText = await response.text();
  } catch (error: unknown) {
    throw new ApiRequestError(`Could not read API response: ${opts.method} ${url}`, {
      code: "UPSTREAM_RESPONSE_ERROR", httpStatus: response.status, upstream: context,
      automaticRetryAllowed: false, guidance: guidance(response.status, opts.method),
    }, { cause: error });
  }

  if (!response.ok) {
    const safeText = responseText.replaceAll(opts.token, "[REDACTED]");
    const body = errorBody(safeText);
    const inner = object(body.innerError ?? body.innererror);
    throw new ApiRequestError(`API ${opts.method} ${opts.path} failed (${response.status}): ${safeText.slice(0, 2000)}`, {
      code: "UPSTREAM_HTTP_ERROR",
      httpStatus: response.status,
      upstream: {
        ...context,
        errorCode: typeof body.code === "string" ? body.code : undefined,
        requestId: context.requestId ?? inner["request-id"],
        date: context.date ?? inner.date,
      },
      automaticRetryAllowed: false,
      guidance: guidance(response.status, opts.method),
    });
  }

  if (!responseText) return { httpStatus: response.status };
  try {
    return JSON.parse(responseText);
  } catch (error: unknown) {
    if (!(error instanceof SyntaxError)) throw error;
    throw new ApiRequestError(`API ${opts.method} ${opts.path} returned invalid JSON`, {
      code: "INVALID_UPSTREAM_RESPONSE", httpStatus: response.status, upstream: context,
      automaticRetryAllowed: false, guidance: guidance(undefined, opts.method),
    }, { cause: error });
  }
}

export async function apiRequest(opts: ApiRequestOptions): Promise<unknown> {
  if (!opts.token) throw new ApiRequestError("Missing user access token", { code: "AUTHENTICATION_REQUIRED", automaticRetryAllowed: false });
  const baseUrl = opts.base === "graph" ? GRAPH_BASE : DEFENDER_BASE;
  const url = new URL(`${baseUrl}${opts.path}`);
  for (const [key, value] of Object.entries(opts.params ?? {})) url.searchParams.set(key, value);
  return request(url.toString(), opts);
}

export async function defenderNextPage(nextLink: string, path: string, token: string): Promise<unknown> {
  if (!URL.canParse(nextLink)) throw new Error("Defender returned an invalid pagination URL");
  const url = new URL(nextLink);
  if (url.origin !== new URL(DEFENDER_BASE).origin || url.pathname !== `/api${path}` || url.username || url.password || url.hash) {
    throw new Error("Defender returned an unexpected pagination URL; no token was forwarded");
  }
  return request(url.toString(), { base: "defender", method: "GET", path, token });
}

export function toolErrorDetails(error: unknown, tool: string, args: Record<string, unknown>) {
  const target: Record<string, string> = {};
  if (typeof args === "object" && args !== null && !Array.isArray(args)) {
    for (const key of ["machineId", "actionId", "incidentId", "hostname"]) {
      if (typeof args[key] === "string") target[key] = args[key];
    }
  }
  return {
    error: error instanceof Error ? error.message : String(error),
    diagnostics: {
      code: "TOOL_ERROR",
      automaticRetryAllowed: false,
      ...(error instanceof ApiRequestError ? error.diagnostics : {}),
      tool,
      target,
    },
  };
}

export function extractToken(req: Request): string {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ") || !auth.slice(7).trim()) {
    throw new ApiRequestError("Missing or invalid Authorization header", {
      code: "AUTHENTICATION_REQUIRED",
      automaticRetryAllowed: false,
      guidance: ["Authenticate the Defender or Graph connection with a token for the correct API audience."],
    });
  }
  return auth.slice(7);
}
