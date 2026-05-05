# response-actions-mcp

Stateless MCP server for SOC incident response actions via Microsoft Graph and Defender for Endpoint APIs with token passthrough.

Built for **Microsoft Copilot Studio** — complementing the [sentinel-triage-mcp](../sentinel-triage-mcp) with write actions for containment and remediation.

## Deploy to Azure

Click the button below to deploy to Azure Container Apps:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fbrunofreitas-br%2FCustom-MCP-Servers%2Fmain%2Fresponse-actions-mcp%2Finfra%2Fazuredeploy.json)

### Build and push your image

```bash
az group create --name rg-response-actions-mcp --location eastus

az containerapp up \
  --name response-actions-mcp \
  --resource-group rg-response-actions-mcp \
  --source . \
  --ingress external \
  --target-port 3001 \
  --env-vars "PORT=3001"
```

## Features

- **10 response tools** — identity actions (block, unblock, revoke, reset) + device actions (isolate, unisolate, AV scan, restrict/unrestrict apps, collect forensics)
- **Token passthrough** — zero credentials stored server-side; each user's Bearer token is forwarded directly to Microsoft APIs
- **Fully stateless** — no sessions, no state, scales to zero on Azure Container Apps
- **Audit trail** — every action requires an `incidentId` parameter for traceability

## Tools

| # | Tool | Description | API |
|---|------|-------------|-----|
| 1 | `block_user` | Disable user sign-in in Entra ID | Graph |
| 2 | `unblock_user` | Re-enable user sign-in | Graph |
| 3 | `revoke_sessions` | Invalidate all refresh tokens | Graph |
| 4 | `reset_user_password` | Reset password, force change at next sign-in | Graph |
| 5 | `isolate_device` | Network isolation (Full/Selective) via MDE | Defender |
| 6 | `unisolate_device` | Release device from isolation | Defender |
| 7 | `run_antivirus_scan` | Trigger Quick or Full AV scan | Defender |
| 8 | `restrict_app_execution` | Block non-Microsoft-signed apps | Defender |
| 9 | `unrestrict_app_execution` | Remove app execution restriction | Defender |
| 10 | `collect_investigation_package` | Collect forensic evidence package | Defender |

## Setup Guide

### Step 1: Create an App Registration

1. Go to [Azure Portal](https://portal.azure.com/) → Microsoft Entra ID → App registrations → New registration
2. Name: `SOC Response Actions MCP`
3. Supported account types: Accounts in this organizational directory only
4. Click Register

#### Add API permissions

**Microsoft Graph (Delegated):**
- `User.ReadWrite.All` — block/unblock user, reset password
- `User.RevokeSessions.All` — revoke sign-in sessions

**WindowsDefenderATP (Delegated):**
- `Machine.Isolate` — isolate/unisolate device
- `Machine.Scan` — run AV scan
- `Machine.RestrictExecution` — restrict/unrestrict apps
- `Machine.CollectForensics` — collect investigation package

Click **Grant admin consent**.

#### Create a client secret

1. Go to Certificates & secrets → New client secret
2. Copy the secret Value immediately

#### Note your IDs

From the Overview page, copy:
- Application (client) ID
- Directory (tenant) ID

### Step 2: Configure in Copilot Studio

1. Open your agent in [Copilot Studio](https://copilotstudio.microsoft.com/) → Tools → Add tool
2. Click + New tool → select Model Context Protocol
3. Fill in:

| Field | Value |
|-------|-------|
| Server name | SOC Response Actions |
| Server description | Response actions for SOC incident containment and remediation |
| Server URL | `https://<YOUR_CONTAINER_APP>.azurecontainerapps.io/mcp` |
| Authentication | OAuth 2.0 |

4. Select Manual, then:

| Field | Value |
|-------|-------|
| Client ID | Your Application (client) ID |
| Client secret | Your secret value |
| Authorization URL | `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize` |
| Token URL template | `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token` |
| Refresh URL | `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token` |
| Scopes | `https://graph.microsoft.com/.default` |

5. Click Create → copy the Redirect URI

### Step 3: Add the Redirect URI

1. Azure Portal → your App Registration → Authentication
2. Add a platform → Web → paste the Redirect URI
3. Click Configure

### Step 4: Create the connection

1. Back in Copilot Studio → Next → Create new connection
2. Sign in with your Microsoft account
3. Green checkmark ✅ → Add and configure
4. The 10 tools should appear under Tools

## How It Works

```
Copilot Studio / Any MCP Client
        │
        │  POST /mcp
        │  Authorization: Bearer <user-token>
        │  {"jsonrpc":"2.0","method":"tools/call","params":{"name":"block_user",...}}
        ▼
┌──────────────────────────┐
│  response-actions-mcp    │  ← Stateless, holds ZERO credentials
│  (Azure Container Apps)  │
└──────────┬───────────────┘
           │  Forwards user's token as-is
           ├──► Microsoft Graph API (identity actions)
           │    PATCH /users/{id}, POST revokeSignInSessions
           └──► Defender for Endpoint API (device actions)
                POST /machines/{id}/isolate, runAntiVirusScan, etc.
```

⚠️ **Important**: Device actions use the Defender for Endpoint API (`api.securitycenter.microsoft.com`), which requires a **separate token** with `https://api.securitycenter.microsoft.com/.default` scope. For Copilot Studio, you may need to configure two scopes or use a multi-resource consent flow. An alternative is to use Power Automate flows for the Defender actions (see `connectors/response-actions.md` in the copilot-studio folder).

## Required Permissions

| Permission | Type | Purpose |
|------------|------|---------|
| `User.ReadWrite.All` | Delegated | Block/unblock user, reset password |
| `User.RevokeSessions.All` | Delegated | Revoke sign-in sessions |
| `Machine.Isolate` | Delegated | Isolate/unisolate device |
| `Machine.Scan` | Delegated | Run AV scan |
| `Machine.RestrictExecution` | Delegated | Restrict/unrestrict app execution |
| `Machine.CollectForensics` | Delegated | Collect investigation package |

The user authenticating must have **Security Operator** role (minimum) in the Defender portal.

## Local Development

```bash
npm install
npm run build
PORT=3001 node dist/server.js
```

Test:
```bash
# Health check
curl http://localhost:3001/health

# List tools
curl -X POST http://localhost:3001/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Project Structure

```
response-actions-mcp/
├── src/
│   ├── server.ts          # Express + stateless JSON-RPC handler
│   ├── apiClient.ts       # Graph/Defender API client with token passthrough
│   ├── toolRegistry.ts    # Tool registration and lookup
│   └── tools/
│       ├── index.ts       # Registers all tools
│       ├── identity.ts    # block_user, unblock_user, revoke_sessions, reset_password
│       └── devices.ts     # isolate, unisolate, av_scan, restrict, unrestrict, collect_package
├── infra/
│   └── azuredeploy.json   # ARM template for Deploy to Azure button
├── Dockerfile
├── package.json
├── tsconfig.json
└── .env.example
```

## License

MIT
