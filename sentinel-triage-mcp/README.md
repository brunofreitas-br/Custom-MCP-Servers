# sentinel-triage-mcp

Stateless MCP server that proxies Microsoft Graph Security API for incident triage and threat hunting.

Built for **Microsoft Copilot Studio** — where the official [Sentinel Triage MCP collection](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool) is not natively available as a built-in tool.

## Deploy to Azure

Click the button below to deploy the MCP server to Azure Container Apps:

> **Note:** After deploying, update the `containerImage` parameter with your own container registry image. See [Build and push your image](#build-and-push-your-image) below.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fbrunofreitas-br%2FCustom-MCP-Servers%2Fmain%2Fsentinel-triage-mcp%2Finfra%2Fazuredeploy.json)

### Build and push your image

If you prefer to build and deploy manually via CLI:

```bash
az group create --name rg-sentinel-triage-mcp --location eastus

az containerapp up \
  --name sentinel-triage-mcp \
  --resource-group rg-sentinel-triage-mcp \
  --source . \
  --ingress external \
  --target-port 3000 \
  --env-vars "PORT=3000"
```

After deployment, note your **Container App URL** (e.g., `https://sentinel-triage-mcp.<random>.azurecontainerapps.io`). You'll need it for the Copilot Studio setup.

---

## Features

- **7 security tools** — incidents, alerts, and advanced hunting (KQL)
- **Token passthrough** — zero credentials stored server-side; each user's Bearer token is forwarded directly to Microsoft Graph
- **Fully stateless** — no sessions, no state, scales to zero on Azure Container Apps
- **Tenant-agnostic** — deploy once, use from any tenant with its own App Registration

## Tools

| # | Tool | Description |
|---|------|-------------|
| 1 | `ListIncidents` | List and filter security incidents by severity, status, date range, analyst |
| 2 | `GetIncidentById` | Get incident details with optional correlated alerts |
| 3 | `ListAlerts` | List and filter security alerts |
| 4 | `GetAlertById` | Get full alert details including evidence and MITRE techniques |
| 5 | `FetchAdvancedHuntingTablesOverview` | List available advanced hunting tables |
| 6 | `FetchAdvancedHuntingTablesDetailedSchema` | Get column schemas for KQL query building |
| 7 | `RunAdvancedHuntingQuery` | Execute KQL queries across Defender tables |

---

## Setup Guide

### Step 1: Create an App Registration

This needs to be done **once per tenant** that will use the MCP server.

1. Go to the [Azure Portal](https://portal.azure.com) → **Microsoft Entra ID** → **App registrations** → **New registration**
2. Fill in:
   - **Name:** `Sentinel Triage MCP`
   - **Supported account types:** Accounts in this organizational directory only
3. Click **Register**

#### Add API permissions

1. In your new App Registration, go to **API permissions** → **Add a permission**
2. Select **Microsoft Graph** → **Delegated permissions**
3. Search for and add these three permissions:
   - `SecurityIncident.Read.All`
   - `SecurityAlert.Read.All`
   - `ThreatHunting.Read.All`
4. Click **Add permissions**
5. Click **Grant admin consent for \<your tenant\>** → **Yes**

#### Create a client secret

1. Go to **Certificates & secrets** → **Client secrets** → **New client secret**
2. Add a description (e.g., `mcp-proxy`) and set an expiration
3. Click **Add**
4. **Copy the secret Value immediately** — you won't be able to see it again

#### Note your IDs

From the App Registration **Overview** page, copy and save:
- **Application (client) ID**
- **Directory (tenant) ID**

---

### Step 2: Configure in Copilot Studio

1. Open your agent in [Copilot Studio](https://copilotstudio.microsoft.com) → **Tools** → **Add tool**
2. Click **+ New tool** → select **Model Context Protocol**
3. Fill in the fields:

| Field | Value |
|-------|-------|
| **Server name** | `Sentinel Triage` |
| **Server description** | `Triage incidents and hunt for threats using Microsoft Graph Security API` |
| **Server URL** | `https://<YOUR_CONTAINER_APP>.azurecontainerapps.io/mcp` |
| **Authentication** | **OAuth 2.0** |

4. Select **Manual** as the OAuth type, then fill in:

| OAuth Field | Value |
|------------|-------|
| **Client ID** | Your Application (client) ID |
| **Client secret** | The secret value you copied |
| **Authorization URL** | `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize` |
| **Token URL template** | `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token` |
| **Refresh URL** | `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token` |
| **Scopes** | `https://graph.microsoft.com/.default` |

5. Click **Create** → a **Redirect URI** will be generated — **copy it**

---

### Step 3: Add the Redirect URI

1. Go back to the [Azure Portal](https://portal.azure.com) → your App Registration → **Authentication**
2. Click **Add a platform** → **Web**
3. Paste the **Redirect URI** from Copilot Studio
4. Click **Configure**

---

### Step 4: Create the connection

1. Back in Copilot Studio → click **Next** → **Create new connection**
2. Sign in with your Microsoft account
3. If you see a green checkmark ✅ → click **Add and configure**
4. The 7 tools should now appear under the **Tools** section

---

## Use in VS Code (optional)

You can also connect to this MCP server from VS Code. Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "sentinel-triage": {
      "type": "http",
      "url": "https://<YOUR_CONTAINER_APP>.azurecontainerapps.io/mcp"
    }
  }
}
```

---

## How It Works

```
Copilot Studio / VS Code / Any MCP Client
        │
        │  POST /mcp
        │  Authorization: Bearer <user-token>
        │  {"jsonrpc":"2.0","method":"tools/call","params":{"name":"ListIncidents",...}}
        ▼
┌──────────────────────────┐
│  sentinel-triage-mcp     │  ← Stateless, holds ZERO credentials
│  (Azure Container Apps)  │
└──────────┬───────────────┘
           │  Forwards user's token as-is
           ▼
    Microsoft Graph
    Security API
    GET /v1.0/security/incidents
    Authorization: Bearer <user-token>
```

No OBO, no client credentials, no secrets on the server — pure token passthrough. Each user only sees what their RBAC permissions allow.

## Required Permissions

| Permission | Type | Purpose |
|------------|------|---------|
| `SecurityIncident.Read.All` | Delegated | List and read incidents |
| `SecurityAlert.Read.All` | Delegated | List and read alerts |
| `ThreatHunting.Read.All` | Delegated | Run advanced hunting queries (KQL) |

The user authenticating must also have **Security Reader** (minimum) role assigned in the [Microsoft Defender portal](https://security.microsoft.com).

---

## Local Development

```bash
npm install
npm run build
PORT=3000 node dist/server.js
```

Test:
```bash
# Health check
curl http://localhost:3000/health

# List available tools
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Project Structure

```
sentinel-triage-mcp/
├── src/
│   ├── server.ts          # Express + stateless JSON-RPC handler
│   ├── apiClient.ts       # Graph API client with token passthrough
│   ├── toolRegistry.ts    # Tool registration and lookup
│   └── tools/
│       ├── index.ts       # Registers all tools
│       ├── incidents.ts   # ListIncidents, GetIncidentById
│       ├── alerts.ts      # ListAlerts, GetAlertById
│       └── hunting.ts     # Tables overview, schema, RunHuntingQuery
├── infra/
│   └── azuredeploy.json   # ARM template for Deploy to Azure button
├── Dockerfile
├── package.json
├── tsconfig.json
└── .env.example
```

## License

MIT
