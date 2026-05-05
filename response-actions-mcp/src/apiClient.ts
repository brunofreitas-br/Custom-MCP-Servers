import { Request, Response } from "express";

const GRAPH_BASE = "https://graph.microsoft.com/v1.0";
const DEFENDER_BASE = "https://api.securitycenter.microsoft.com/api";

export interface ApiRequestOptions {
  base: "graph" | "defender";
  method: string;
  path: string;
  body?: Record<string, unknown> | null;
  token: string;
}

export async function apiRequest(opts: ApiRequestOptions): Promise<unknown> {
  const baseUrl = opts.base === "graph" ? GRAPH_BASE : DEFENDER_BASE;
  const url = `${baseUrl}${opts.path}`;

  const headers: Record<string, string> = {
    Authorization: `Bearer ${opts.token}`,
    "Content-Type": "application/json",
  };

  const fetchOpts: RequestInit = { method: opts.method, headers };
  if (opts.body) {
    fetchOpts.body = JSON.stringify(opts.body);
  }

  const response = await fetch(url, fetchOpts);
  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(
      `API ${opts.method} ${opts.path} failed (${response.status}): ${responseText.slice(0, 500)}`
    );
  }

  return responseText ? JSON.parse(responseText) : { status: "success", httpStatus: response.status };
}

export function extractToken(req: Request): string {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    throw new Error("Missing or invalid Authorization header");
  }
  return auth.slice(7);
}
