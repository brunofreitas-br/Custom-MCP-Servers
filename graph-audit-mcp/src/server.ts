import { pathToFileURL } from 'node:url';
import cors from 'cors';
import express from 'express';
import { graphErrorDiagnostics, userTokenStore } from './apiClient.js';
import { getTool, listTools } from './toolRegistry.js';
import './tools.js';

const SERVER_NAME = 'graph-audit-mcp';
const SERVER_VERSION = '1.0.0';
const PROTOCOL_VERSION = '2025-03-26';

interface JsonRpcRequest {
  jsonrpc?: unknown;
  id?: unknown;
  method?: unknown;
  params?: unknown;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: unknown;
  result?: unknown;
  error?: { code: number; message: string };
}

function tokenFromAuthorization(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const match = /^Bearer ([^\s]+)$/iu.exec(header);
  return match?.[1];
}

function toolFailure(error: unknown, tool: string): Record<string, unknown> {
  return {
    error: error instanceof Error ? error.message : 'Unexpected tool failure',
    diagnostics: { ...graphErrorDiagnostics(error), tool },
  };
}

async function handleMessage(message: unknown): Promise<JsonRpcResponse | null> {
  if (typeof message !== 'object' || message === null || Array.isArray(message)) {
    return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid JSON-RPC request' } };
  }
  const { jsonrpc, id, method, params } = message as JsonRpcRequest;
  if (jsonrpc !== '2.0' || typeof method !== 'string') {
    return { jsonrpc: '2.0', id: id ?? null, error: { code: -32600, message: 'Invalid JSON-RPC request' } };
  }
  if (id === undefined || id === null) return null;

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      },
    };
  }
  if (method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: listTools() } };
  }
  if (method === 'tools/call') {
    if (typeof params !== 'object' || params === null || Array.isArray(params)) {
      return { jsonrpc: '2.0', id, error: { code: -32602, message: 'params must be an object' } };
    }
    const rpcParams = params as Record<string, unknown>;
    if (typeof rpcParams.name !== 'string') {
      return { jsonrpc: '2.0', id, error: { code: -32602, message: 'Missing tool name in params.name' } };
    }
    const tool = getTool(rpcParams.name);
    if (!tool) {
      return { jsonrpc: '2.0', id, error: { code: -32601, message: `Tool not found: ${rpcParams.name}` } };
    }
    const args = rpcParams.arguments ?? {};
    if (typeof args !== 'object' || args === null || Array.isArray(args)) {
      return { jsonrpc: '2.0', id, error: { code: -32602, message: 'Tool arguments must be an object' } };
    }
    try {
      const result = await tool.handler(args as Record<string, unknown>);
      return {
        jsonrpc: '2.0',
        id,
        result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] },
      };
    } catch (error: unknown) {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(toolFailure(error, tool.name), null, 2) }],
          isError: true,
        },
      };
    }
  }
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
}

export function createApp(): express.Express {
  const app = express();
  app.use(cors({
    origin: '*',
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));
  app.use(express.json({ limit: '1mb' }));
  app.use((error: unknown, _request: express.Request, response: express.Response, next: express.NextFunction) => {
    if (error instanceof SyntaxError) {
      response.status(400).json({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      });
      return;
    }
    next(error);
  });

  app.get('/health', (_request, response) => {
    response.json({
      status: 'ok',
      server: SERVER_NAME,
      version: SERVER_VERSION,
      tools: listTools().length,
      authMode: 'token-passthrough',
      stateless: true,
    });
  });

  app.post('/mcp', async (request, response) => {
    const token = tokenFromAuthorization(request.headers.authorization);
    await userTokenStore.run(token, async () => {
      if (Array.isArray(request.body)) {
        if (request.body.length === 0) {
          response.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid empty JSON-RPC batch' } });
          return;
        }
        const results = (await Promise.all(request.body.map(handleMessage))).filter((item) => item !== null);
        if (results.length === 0) {
          response.status(204).end();
          return;
        }
        response.json(results);
        return;
      }
      const result = await handleMessage(request.body);
      if (result === null) {
        response.status(204).end();
        return;
      }
      response.json(result);
    });
  });

  app.use((_request, response) => {
    response.status(404).json({
      error: 'MCP_ENDPOINT_NOT_FOUND',
      message: 'Use POST /mcp for MCP JSON-RPC. No Microsoft Graph request was made.',
      expectedEndpoints: ['/mcp'],
    });
  });
  return app;
}

export function startServer(port = Number(process.env.PORT) || 3000): ReturnType<express.Express['listen']> {
  return createApp().listen(port, () => {
    console.log(`Graph Audit MCP server listening on port ${port}`);
    console.log(`  MCP endpoint: http://localhost:${port}/mcp`);
    console.log(`  Health check: http://localhost:${port}/health`);
    console.log(`  Tools: ${listTools().length}`);
    console.log('  Mode: stateless token-passthrough (no sessions, cache, datastore, or stored credentials)');
  });
}

const entryPoint = process.argv[1] ? pathToFileURL(process.argv[1]).href : undefined;
if (entryPoint === import.meta.url) startServer();
