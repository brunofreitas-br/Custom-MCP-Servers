# Custom MCP Servers for Security Operations

A collection of custom [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers that bring security operations capabilities to AI platforms like **Microsoft Copilot Studio**, **VS Code**, and other MCP-compatible clients.

## The Problem

Microsoft provides powerful MCP server collections for security operations (incident triage, threat hunting, data exploration), but **not all collections are available on all platforms**. For example:

| Sentinel MCP Collection | VS Code | Copilot Studio | Security Copilot |
|------------------------|---------|---------------|-----------------|
| Data Exploration | ✅ | ✅ Built-in | ✅ |
| Graph MCP Server | ✅ | ✅ Built-in | ✅ |
| **Triage & Hunting** | ✅ | ❌ **Not available** | ✅ |

The official Triage collection uses an app identity allowlist that blocks third-party App Registrations — meaning it works in VS Code (first-party Microsoft app) but **cannot be added as a custom MCP tool in Copilot Studio**.

## The Solution

This repo provides custom MCP servers that call the **same underlying APIs** (Microsoft Graph Security, Defender for Endpoint) directly, bypassing the allowlist limitation. They work with any MCP client, including Copilot Studio.

### Key Design Principles

- **Token passthrough** — The servers hold **zero credentials**. The user's OAuth token is forwarded directly to the downstream API. No secrets to manage, rotate, or leak.
- **Stateless** — No sessions, no state. Every request is independent. Scales to zero on Azure Container Apps.
- **Tenant-agnostic** — Deploy once, use from any tenant. Each tenant creates its own App Registration pointing to the shared server.
- **RBAC-respecting** — Each analyst only sees data their permissions allow, because the API call runs as them.

## Available Servers

| Server | Description | Tools | Status |
|--------|-------------|-------|--------|
| [sentinel-triage-mcp](./sentinel-triage-mcp/) | Incident triage & threat hunting via Microsoft Graph Security API | 7 | ✅ Production |
| [response-actions-mcp](./response-actions-mcp/) | SOC response actions (containment & remediation) via Microsoft Graph and Defender for Endpoint APIs | 10 | ✅ Production |

### sentinel-triage-mcp

Read-only triage and threat hunting. Lists incidents, inspects alerts, runs KQL hunting queries against Microsoft Sentinel — all via the Microsoft Graph Security API.

### response-actions-mcp

Write actions for containment and remediation. Companion to `sentinel-triage-mcp` — after triaging an incident, use this server to take action.

Exposes **two separate MCP endpoints** to support the two different OAuth scopes required by Copilot Studio:

| Endpoint | API | Tools | Permissions (Delegated) |
|----------|-----|-------|------------------------|
| `/mcp/identity` | Microsoft Graph | `block_user`, `unblock_user`, `revoke_sessions`, `reset_user_password` | `User.ReadWrite.All`, `User.RevokeSessions.All` |
| `/mcp/devices` | Defender for Endpoint | `isolate_device`, `unisolate_device`, `run_antivirus_scan`, `restrict_app_execution`, `unrestrict_app_execution`, `collect_investigation_package` | `Machine.Isolate`, `Machine.Scan`, `Machine.RestrictExecution`, `Machine.CollectForensics` |

## Planned Servers

As Microsoft evolves its MCP support, gaps may emerge in other areas. Potential future additions:

| Server | Description | Status |
|--------|-------------|--------|
| `entra-identity-mcp` | Identity investigation — risky users, sign-in logs, conditional access | 💡 Idea |

## Architecture

```
┌─────────────────────────────────────────────────┐
│           Copilot Studio / VS Code              │
│              (MCP Client)                       │
└──────────────────┬──────────────────────────────┘
                   │ OAuth 2.0 (user's Bearer token)
                   ▼
┌─────────────────────────────────────────────────┐
│         Custom MCP Server                       │
│         (Azure Container Apps)                  │
│                                                 │
│   • Stateless JSON-RPC endpoint                 │
│   • Zero credentials stored                     │
│   • Forwards user token as-is                   │
└──────────────────┬──────────────────────────────┘
                   │ Bearer token passthrough
                   ▼
┌─────────────────────────────────────────────────┐
│       Microsoft Graph Security API              │
│       Defender for Endpoint API                 │
│       (responds based on user's RBAC)           │
└─────────────────────────────────────────────────┘
```

## Getting Started

Each server has its own README with detailed setup instructions. The general flow is:

1. **Deploy** the MCP server to Azure Container Apps (one-click or CLI)
2. **Create an App Registration** in the target tenant (Azure Portal)
3. **Add the MCP tool** to your Copilot Studio agent with OAuth 2.0
4. **Start prompting** — triage incidents, hunt for threats, investigate alerts

See the [sentinel-triage-mcp README](./sentinel-triage-mcp/README.md) and the [response-actions-mcp README](./response-actions-mcp/README.md) for full step-by-step guides.

## Contributing

Found a gap in Microsoft's MCP coverage? Have an idea for a new security MCP server? Contributions are welcome:

1. Fork the repo
2. Create a new folder for your MCP server (e.g., `defender-endpoint-mcp/`)
3. Follow the same patterns: token passthrough, stateless, no hardcoded credentials
4. Submit a PR

## License

MIT
