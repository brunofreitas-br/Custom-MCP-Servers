# sentinel-triage-mcp

Stateless MCP server that proxies Microsoft Graph Security API for incident triage, alert/incident updates, and threat hunting.

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

- **9 security tools** — incidents, alerts, updates/closure, and advanced hunting (KQL)
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
| 8 | `UpdateIncident` | Update incident fields, including closing with `status: "resolved"` |
| 9 | `UpdateAlert` | Update alert fields, including closing with `status: "resolved"` |

## Updating and closing incidents or alerts

The update tools use `PATCH` on Microsoft Graph v1.0. Supply the resource ID and at least one supported field. Only explicitly supplied fields are sent; the server never chooses a classification or determination for you. Microsoft Graph can recalculate related properties according to its own lifecycle rules.

| Tool | Supported update fields |
|------|-------------------------|
| `UpdateIncident` | `status`, `assignedTo`, `classification`, `determination`, `severity`, `displayName`, `description`, `summary`, `resolvingComment`, `customTags` |
| `UpdateAlert` | `status`, `assignedTo`, `classification`, `determination`, `customDetails` |

- Incident statuses: `active`, `resolved`, `redirected`. Use `active` to reopen.
- Alert statuses: `new`, `inProgress`, `resolved`. Use `inProgress` to resume investigation.
- Use `assignedTo: null` to remove an assignment and `customTags: []` to clear incident tags.
- Alert `customDetails` must be an object with string values.
- Unsupported fields, invalid types/statuses, and empty updates fail before an API call.
- These tools are write actions. Confirm the target and intended changes before invoking them.

Example JSON-RPC request to close an incident:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "UpdateIncident",
    "arguments": {
      "incidentId": "29",
      "status": "resolved",
      "classification": "truePositive",
      "determination": "malware",
      "resolvingComment": "Confirmed malware; containment and investigation completed."
    }
  }
}
```

To close an alert, call `UpdateAlert` with `alertId` and `status: "resolved"`, optionally supplying its classification, determination, assignment, or custom details. Both tools return the updated Graph resource through the existing MCP text-content format.

API references: [Update incident](https://learn.microsoft.com/en-us/graph/api/security-incident-update?view=graph-rest-1.0) and [Update alert](https://learn.microsoft.com/en-us/graph/api/security-alert-update?view=graph-rest-1.0).

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
   - `SecurityIncident.ReadWrite.All`
   - `SecurityAlert.ReadWrite.All`
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
4. The 9 tools should now appear under the **Tools** section

For an existing deployment, grant admin consent for the new read/write permissions, reconnect the OAuth connection to obtain a token with the new permissions, and refresh the tools after redeploying. Read-only connections can continue using the original seven tools but cannot perform updates.

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
| `SecurityIncident.ReadWrite.All` | Delegated | Read, update, and close incidents |
| `SecurityAlert.ReadWrite.All` | Delegated | Read, update, and close alerts |
| `ThreatHunting.Read.All` | Delegated | Run advanced hunting queries (KQL) |

The read/write permissions also cover reading their respective resources; there is no need to add the corresponding read-only permissions when using read/write. Keep read-only permissions for connections intended only for investigation.

Reading requires the relevant security-reader access. Updating incidents or alerts also requires the signed-in user's **Security Operator** or **Security Administrator** Microsoft Entra role, or an equivalent custom role, plus applicable Defender RBAC access. OAuth permission consent alone does not grant the user those roles.

---

## Local Development

```bash
npm install
npm run build
PORT=3000 node dist/server.js
```

Automated tests:

```bash
npm test
```

This builds the project and runs Node's built-in tests, including local HTTP MCP requests, with all Graph calls mocked. Docker builds run the same tests before producing the runtime image.

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
│   ├── updateValidation.ts # Shared validation for partial Graph updates
│   └── tools/
│       ├── index.ts       # Registers all tools
│       ├── incidents.ts   # ListIncidents, GetIncidentById, UpdateIncident
│       ├── alerts.ts      # ListAlerts, GetAlertById, UpdateAlert
│       └── hunting.ts     # Tables overview, schema, RunHuntingQuery
├── test/
│   └── tools.test.js      # Tool contracts, validation, regressions, HTTP MCP
├── infra/
│   └── azuredeploy.json   # ARM template for Deploy to Azure button
├── Dockerfile
├── package.json
├── tsconfig.json
└── .env.example
```

## License

MIT
