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
| [sentinel-triage-mcp](./sentinel-triage-mcp/) | Incident triage, alert/incident updates & threat hunting via Microsoft Graph Security API | 9 | ✅ Production |
| [response-actions-mcp](./response-actions-mcp/) | SOC response actions, indicator blocking & file quarantine via Microsoft Graph and Defender for Endpoint APIs | 12 | ✅ Production |

### sentinel-triage-mcp

Incident triage, management, and threat hunting via Microsoft Graph Security API. Lists incidents, inspects alerts, runs KQL hunting queries, and updates or closes incidents and alerts. Updates require the delegated `SecurityIncident.ReadWrite.All` or `SecurityAlert.ReadWrite.All` permission; existing read-only permissions remain sufficient for reading.

### response-actions-mcp

Write actions for containment and remediation. Companion to `sentinel-triage-mcp` — after triaging an incident, use this server to take action.

Exposes **two separate MCP endpoints** to support the two different OAuth scopes required by Copilot Studio:

| Endpoint | API | Tools | Permissions (Delegated) |
|----------|-----|-------|------------------------|
| `/mcp/identity` | Microsoft Graph | `block_user`, `unblock_user`, `revoke_sessions`, `reset_user_password` | `User.ReadWrite.All`, `User.RevokeSessions.All` |
| `/mcp/devices` | Defender for Endpoint | `isolate_device`, `unisolate_device`, `run_antivirus_scan`, `restrict_app_execution`, `unrestrict_app_execution`, `collect_investigation_package`, `block_indicator`, `stop_and_quarantine_file` | `Machine.Isolate`, `Machine.Scan`, `Machine.RestrictExecution`, `Machine.CollectForensics`, `Ti.ReadWrite`, `Machine.StopAndQuarantine` |

Indicator blocking supports URLs, domains, IP addresses, file hashes, and certificate thumbprints. Every call must explicitly choose device groups or all devices in the tenant. File removal uses Defender's native stop-and-quarantine action on a device and SHA-1 hash, not permanent deletion by file path. Both actions return the Defender resource for tracking; submission does not imply completed enforcement.

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

For an existing deployment, redeploy the updated image, grant admin consent for the new delegated permissions, reconnect the affected OAuth connections, and refresh the MCP tools in the client. The existing endpoint URLs are unchanged.

## Tests

```bash
npm --prefix sentinel-triage-mcp test
npm --prefix response-actions-mcp test
```

Each command compiles TypeScript and runs Node's built-in test runner. Tests cover payloads, validation, token handling, existing tools, and local HTTP MCP endpoints with mocked downstream APIs. No tenant actions are executed. Docker builds also run these tests before producing the runtime image.

## Contributing

Found a gap in Microsoft's MCP coverage? Have an idea for a new security MCP server? Contributions are welcome:

1. Fork the repo
2. Create a new folder for your MCP server (e.g., `defender-endpoint-mcp/`)
3. Follow the same patterns: token passthrough, stateless, no hardcoded credentials
4. Submit a PR

## License

MIT
