import express from "express";
import { listTools, getTool, type ToolCollection } from "./toolRegistry.js";
import { extractToken } from "./apiClient.js";
import "./tools/index.js";

const app = express();
app.use(express.json());

// ── Health check ────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    collections: {
      identity: listTools("identity").length,
      devices: listTools("devices").length,
    },
    totalTools: listTools().length,
  });
});

// ── Collection-to-server info mapping ───────────────────────────────────────
const SERVER_INFO: Record<ToolCollection, { name: string; description: string }> = {
  identity: {
    name: "SOC Response — Identity",
    description: "Identity response actions (block/unblock user, revoke sessions, reset password) via Microsoft Graph API",
  },
  devices: {
    name: "SOC Response — Devices",
    description: "Device response actions (isolate, AV scan, restrict apps, collect forensics) via Defender for Endpoint API",
  },
};

// ── MCP JSON-RPC handler (shared logic) ─────────────────────────────────────
function mcpHandler(collection: ToolCollection) {
  return async (req: express.Request, res: express.Response) => {
    const { jsonrpc, id, method, params } = req.body;

    if (jsonrpc !== "2.0") {
      res.status(400).json({ jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid JSON-RPC version" } });
      return;
    }

    try {
      switch (method) {
        case "initialize": {
          res.json({
            jsonrpc: "2.0",
            id,
            result: {
              protocolVersion: "2025-03-26",
              capabilities: { tools: { listChanged: false } },
              serverInfo: { name: SERVER_INFO[collection].name, version: "1.0.0" },
            },
          });
          return;
        }

        case "tools/list": {
          res.json({
            jsonrpc: "2.0",
            id,
            result: { tools: listTools(collection) },
          });
          return;
        }

        case "tools/call": {
          const toolName = params?.name as string;
          const toolArgs = (params?.arguments ?? {}) as Record<string, unknown>;

          const tool = getTool(toolName, collection);
          if (!tool) {
            res.json({
              jsonrpc: "2.0",
              id,
              error: { code: -32601, message: `Unknown tool: ${toolName} (collection: ${collection})` },
            });
            return;
          }

          let token: string;
          try {
            token = extractToken(req);
          } catch {
            res.json({
              jsonrpc: "2.0",
              id,
              error: { code: -32000, message: "Missing or invalid Authorization header. Token passthrough requires a Bearer token." },
            });
            return;
          }

          const result = await tool.handler(toolArgs, token);
          res.json({
            jsonrpc: "2.0",
            id,
            result: {
              content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            },
          });
          return;
        }

        case "notifications/initialized": {
          res.json({ jsonrpc: "2.0", id, result: {} });
          return;
        }

        default: {
          res.json({
            jsonrpc: "2.0",
            id,
            error: { code: -32601, message: `Method not found: ${method}` },
          });
          return;
        }
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.json({
        jsonrpc: "2.0",
        id,
        error: { code: -32000, message },
      });
    }
  };
}

// ── Mount collection-specific endpoints ─────────────────────────────────────
app.post("/mcp/identity", mcpHandler("identity"));
app.post("/mcp/devices", mcpHandler("devices"));

// ── Start server ────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || "3001", 10);
app.listen(PORT, () => {
  console.log(`SOC Response Actions MCP server running on port ${PORT}`);
  console.log(`\nEndpoints:`);
  console.log(`  POST /mcp/identity  — ${listTools("identity").length} tools (Graph API)`);
  listTools("identity").forEach((t) => console.log(`    - ${t.name}`));
  console.log(`  POST /mcp/devices   — ${listTools("devices").length} tools (Defender API)`);
  listTools("devices").forEach((t) => console.log(`    - ${t.name}`));
});
