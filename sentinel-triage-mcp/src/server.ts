import express from 'express';
import cors from 'cors';
import { registerAllTools } from './tools/index.js';
import { listTools, getTool } from './toolRegistry.js';
import { userTokenStore } from './apiClient.js';

const PORT = Number(process.env.PORT) || 3000;
const SERVER_NAME = 'sentinel-triage-proxy';
const SERVER_VERSION = '2.0.0';
const PROTOCOL_VERSION = '2024-11-05';

// ── Register all tools at startup ────────────────────────────────
registerAllTools();

// ── Extract Bearer token from request ────────────────────────────
function extractBearerToken(req: express.Request): string | undefined {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    return auth.slice(7);
  }
  return undefined;
}

// ── JSON-RPC message handler ─────────────────────────────────────
interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id?: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

async function handleMessage(msg: JsonRpcRequest): Promise<JsonRpcResponse | null> {
  // Notifications (no id) — acknowledge silently
  if (msg.id === undefined || msg.id === null) {
    // notifications/initialized, notifications/cancelled, etc.
    return null;
  }

  switch (msg.method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        },
      };

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: { tools: listTools() },
      };

    case 'tools/call': {
      const toolName = msg.params?.name as string | undefined;
      const toolArgs = (msg.params?.arguments ?? {}) as Record<string, unknown>;

      if (!toolName) {
        return {
          jsonrpc: '2.0',
          id: msg.id,
          error: { code: -32602, message: 'Missing tool name in params.name' },
        };
      }

      const tool = getTool(toolName);
      if (!tool) {
        return {
          jsonrpc: '2.0',
          id: msg.id,
          error: { code: -32601, message: `Tool not found: ${toolName}` },
        };
      }

      try {
        const result = await tool.handler(toolArgs);
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
          },
        };
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err);
        return {
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            content: [{ type: 'text', text: `Error: ${errMsg}` }],
            isError: true,
          },
        };
      }
    }

    default:
      return {
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32601, message: `Method not found: ${msg.method}` },
      };
  }
}

// ── Express app ──────────────────────────────────────────────────
const app = express();
app.use(cors({
  origin: '*',
  exposedHeaders: ['mcp-session-id'],
  allowedHeaders: ['Content-Type', 'Authorization', 'mcp-session-id'],
}));
app.use(express.json({ limit: '4mb' }));

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', tools: listTools().length, version: SERVER_VERSION, authMode: 'token-passthrough' });
});

// ── MCP endpoint — fully stateless JSON-RPC ──────────────────────
app.post('/mcp', async (req, res) => {
  const userToken = extractBearerToken(req);

  await userTokenStore.run(userToken, async () => {
    const body = req.body;

    // Batch request (array of messages)
    if (Array.isArray(body)) {
      const results: JsonRpcResponse[] = [];
      for (const msg of body) {
        const result = await handleMessage(msg);
        if (result !== null) {
          results.push(result);
        }
      }
      res.json(results);
      return;
    }

    // Single request
    const result = await handleMessage(body);
    if (result === null) {
      // Notification — no content to return
      res.status(204).end();
      return;
    }
    res.json(result);
  });
});

// ── Start ────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Sentinel Triage MCP Server running on port ${PORT}`);
  console.log(`  MCP endpoint: http://localhost:${PORT}/mcp`);
  console.log(`  Health check: http://localhost:${PORT}/health`);
  console.log(`  Tools: ${listTools().length}`);
  console.log(`  Mode: stateless token-passthrough (no sessions, no credentials)`);
});
