# sentinel-triage-mcp

Stateless MCP server that proxies Microsoft Graph Security API for Cases-first incident triage, case/alert/incident updates, and threat hunting.

> **Preview:** Cases uses Microsoft Graph `/beta`, whose use in production applications is not supported by Microsoft. Cases-first mode is enabled by default. Set `CASE_MANAGEMENT_ENABLED=false` to restore the original `/v1.0/security/incidents` implementation and response shapes.

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

- **14 security tools** — cases, incident references, tenant statuses, incidents, alerts, updates/closure, and advanced hunting (KQL)
- **Cases-first with selective fallback** — existing incident tools prefer Case Management and retain the v1.0 incident implementation
- **Token passthrough** — zero credentials stored server-side; each user's Bearer token is forwarded directly to Microsoft Graph
- **Fully stateless** — no sessions, no state, scales to zero on Azure Container Apps
- **Tenant-agnostic** — deploy once, use from any tenant with its own App Registration

## Tools

| # | Tool | Description |
|---|------|-------------|
| 1 | `ListIncidents` | Cases-first incident listing, with legacy-compatible filters and selective fallback |
| 2 | `GetIncidentById` | Cases-first incident lookup by Incident ID, with separate Case ID and optional correlated alerts |
| 3 | `ListAlerts` | List and filter security alerts |
| 4 | `GetAlertById` | Get full alert details including evidence and MITRE techniques |
| 5 | `FetchAdvancedHuntingTablesOverview` | List available advanced hunting tables |
| 6 | `FetchAdvancedHuntingTablesDetailedSchema` | Get column schemas for KQL query building |
| 7 | `RunAdvancedHuntingQuery` | Execute KQL queries across Defender tables |
| 8 | `UpdateIncident` | Cases-first incident updates, including closing with legacy `status: "resolved"` |
| 9 | `UpdateAlert` | Update alert fields, including closing with `status: "resolved"` |
| 10 | `ListCases` | List incident or generic cases through Graph beta, including filtering by underlying Incident ID |
| 11 | `GetCaseById` | Retrieve a case by its actual Case ID |
| 12 | `ResolveCaseReference` | Explicitly resolve a Case ID or Incident ID; generic cases can link multiple incidents |
| 13 | `ListCaseStatuses` | Read the tenant's status tree, including custom status display names |
| 14 | `UpdateCase` | Update a case by Case ID, with tenant status validation and asynchronous acceptance handling |

## Cases-first triage (preview)

Cases and incidents are related resources, not interchangeable IDs:

- `case.id` is the Case ID (string).
- `incidentCase.incidentId` is the underlying Incident ID (`Int64` in the Graph resource).
- `incidentCase` is created by the service. Generic cases can exist independently and link multiple incidents.
- Reference tools return IDs as strings to avoid converting large identifiers to rounded JavaScript numbers. Unsafe numeric IDs in upstream responses are rejected rather than used to select a resource.

### Lookup and references

`GetIncidentById` searches the derived incident-case collection first:

```http
GET /beta/security/caseManagement/cases/microsoft.graph.security.caseManagement.incidentCase?$filter=incidentId eq 1006
```

The cast is required for filtering on derived properties such as `incidentId`. Zero matches or HTTP 404 triggers the existing `GET /v1.0/security/incidents/{incidentId}`. Multiple matches or malformed responses are explicit errors, not a choice of the first resource.

For a known Case ID, use `GetCaseById`. For an incoming reference, use `ResolveCaseReference` with an explicit `referenceType`; the server never guesses based only on whether an ID looks numeric:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "ResolveCaseReference",
    "arguments": {
      "referenceType": "incident",
      "referenceId": "1006"
    }
  }
}
```

For `referenceType: "case"`, supply the Case ID instead. An incident case yields `caseId` and `incidentId`. A generic case yields all linked `incidentIds` from its relations; it does not choose one implicitly. If an incident reference is found only through the legacy API, the result identifies the incident but does not invent a Case ID.

An unknown Case ID cannot safely be used as an Incident ID for fallback. A case-targeted update can fall back only after its underlying Incident ID has been resolved.

### Lists, filters, and response shapes

- `ListCases` is an explicit beta collection query, defaulting to `caseType: "incidentCase"`; it also supports `genericCase`. It keeps Case IDs as the resource `id`. Empty results stay empty; generic cases aren't fabricated from legacy incidents.
- `ListIncidents` prefers incident cases. It preserves the Incident ID as `id`, adds `caseId` and `caseType`, and includes the original case under `caseDetails`.
- Cases-first incident responses expose the tenant status in `status`/`caseStatus`. These labels can differ from the legacy fixed status enum. Use `caseStatus` and `ListCaseStatuses` for the new lifecycle.
- Legacy status filters are translated using the tenant's status tree, including custom child statuses within that lifecycle family.
- Case queries have a maximum `top` of **100**. `@odata.nextLink` is retained. Reference/status/relation lookups follow continuation pages where needed and reject unexpected URLs.
- Legacy free-text search, unsupported ordering, and larger requested legacy page sizes use the existing incident query intact. Filters are not silently dropped.
- An empty first incident-case page can fall back; an empty later page is an end-of-list, not an automatic switch between paginated data sources.

With Cases-first enabled, results include `_mcp.source` (`cases` or `incidents`), `apiVersion`, and `preview`. A fallback also includes its reason and the original Cases error. With `CASE_MANAGEMENT_ENABLED=false`, existing incident tools return their original unwrapped results.

### Fallback policy and correlated alerts

Fallback is limited to no matching incident case, HTTP 404, or explicit legacy-compatibility routing before a write/query. HTTP 400/401/403/429, server errors, invalid responses, and network failures are returned as errors. If both paths fail, the error includes both failures.

Cases doesn't provide the same `$expand=alerts` contract as incidents. `includeAlertsData` enriches incident-case results through the existing v1.0 incident endpoint with `$expand=alerts`. If the Case exists but that enrichment fails, MCP returns `isError: true` with an explicit message and the found case/incident under `partialResult`; it does not report the Case as missing or invent an empty alerts array.

Explicit Cases tools require Case Management to be enabled. The incident-reference branch of `ResolveCaseReference` can still resolve through the original incident API when Cases is disabled.

References: [List Cases](https://learn.microsoft.com/en-us/graph/api/security-casemanagementroot-list-cases?view=graph-rest-beta), [incidentCase](https://learn.microsoft.com/en-us/graph/api/resources/security-casemanagement-incidentcase?view=graph-rest-beta), and [case management overview](https://learn.microsoft.com/en-us/defender-xdr/siem-defender-case-management).

## Updating and closing incidents or alerts

`UpdateIncident` prefers Case Management beta; `UpdateAlert` remains on Graph v1.0. Supply the resource ID and at least one supported field. Only explicitly supplied fields are sent; the server never chooses a classification or determination for you. Microsoft Graph can recalculate related properties according to its own lifecycle rules.

| Tool | Supported update fields |
|------|-------------------------|
| `UpdateIncident` | `status`, `assignedTo`, `classification`, `determination`, `severity`, `displayName`, `description`, `summary`, `resolvingComment`, `customTags` |
| `UpdateAlert` | `status`, `assignedTo`, `classification`, `determination`, `customDetails` |
| `UpdateCase` (incident case) | `status`, `assignedTo` (non-empty string), `classification`, `determination`, `severity`, `displayName` |
| `UpdateCase` (generic case) | `status`, `assignedTo` (non-empty string), `displayName` |

- Incident statuses: `active`, `resolved`, `redirected`. Use `active` to reopen.
- Alert statuses: `new`, `inProgress`, `resolved`. Use `inProgress` to resume investigation.
- Use `assignedTo: null` to remove an assignment and `customTags: []` to clear incident tags.
- Alert `customDetails` must be an object with string values.
- Unsupported fields, invalid types/statuses, and empty updates fail before an API call.
- These tools are write actions. Confirm the target and intended changes before invoking them.

`UpdateIncident` resolves the incident case and maps the legacy status to a unique matching top-level tenant status before writing. If the status cannot be mapped safely, the original legacy update is used. `description`, `summary`, `resolvingComment`, `customTags`, and assignment clearing with `null` also route the **entire original patch** through `/v1.0/security/incidents`. No update is split between backends.

`UpdateCase` takes a **Case ID** and an exact status **displayName**, including custom statuses, from `ListCaseStatuses`. It currently exposes the fields listed above; other properties such as custom fields and due dates remain available in read results but aren't added to this initial update tool. A custom status cannot be silently translated to a broader legacy status if fallback is required.

For incident-case fields synchronized with the underlying incident, Graph returns **HTTP 202 Accepted without a body**. The MCP returns `result: "ACCEPTED"`, `httpStatus: 202`, `pendingSynchronization: true`, and `submittedChanges`. This is not proof of completion; changes can take a few minutes to appear. An accepted write is never repeated through incidents, and the MCP doesn't automatically poll it. Generic-case updates can return the updated resource with HTTP 200.

To discover the valid tenant lifecycle before a case update:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "ListCaseStatuses",
    "arguments": { "caseType": "incidentCase" }
  }
}
```

Closing an incident case does **not** automatically close its alerts. Use `UpdateAlert` explicitly when appropriate.

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

To close an alert, call `UpdateAlert` with `alertId` and `status: "resolved"`, optionally supplying its classification, determination, assignment, or custom details. Results use the existing MCP text-content format; a Cases update can return acceptance rather than an updated resource.

API references: [Update incident](https://learn.microsoft.com/en-us/graph/api/security-incident-update?view=graph-rest-1.0) and [Update alert](https://learn.microsoft.com/en-us/graph/api/security-alert-update?view=graph-rest-1.0).

Cases references: [Update case](https://learn.microsoft.com/en-us/graph/api/security-casemanagement-case-update?view=graph-rest-beta) and [List statuses](https://learn.microsoft.com/en-us/graph/api/security-casemanagement-casetypeconfiguration-list-statuses?view=graph-rest-beta).

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
3. Search for and add these four permissions for the full Cases-first setup:
   - `CaseManagement.ReadWrite.All`
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
| **Server description** | `Cases-first incident triage, case/incident/alert updates, and threat hunting using Microsoft Graph` |
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
4. The 14 tools should now appear under the **Tools** section

For an existing deployment, add `CaseManagement.ReadWrite.All` (or `CaseManagement.Read.All` for read-only use), grant admin consent, reconnect the OAuth connection to obtain a token with the new permission, and refresh the tools after redeploying. The scope and MCP endpoint remain unchanged.

Missing Cases permission produces an explicit HTTP 403, not a hidden fallback. To keep an existing connection working without granting Cases permissions, set `CASE_MANAGEMENT_ENABLED=false`. The ARM deployment template exposes the equivalent `enableCaseManagement` boolean parameter, defaulting to true.

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
    GET /beta/security/caseManagement/cases/...
      └─ no match / HTTP 404 → /v1.0/security/incidents
    Authorization: Bearer <user-token>
```

No OBO, no client credentials, no secrets on the server — pure token passthrough. Each user only sees what their RBAC permissions allow.

## Required Permissions

| Permission | Type | Purpose |
|------------|------|---------|
| `CaseManagement.Read.All` | Delegated | Read cases, relations, and tenant status definitions |
| `CaseManagement.ReadWrite.All` | Delegated | Read and update cases |
| `SecurityIncident.Read.All` | Delegated | List and read incidents |
| `SecurityAlert.Read.All` | Delegated | List and read alerts |
| `SecurityIncident.ReadWrite.All` | Delegated | Read, update, and close incidents |
| `SecurityAlert.ReadWrite.All` | Delegated | Read, update, and close alerts |
| `ThreatHunting.Read.All` | Delegated | Run advanced hunting queries (KQL) |

The read/write permissions also cover reading their respective resources; there is no need to add the corresponding read-only permissions when using read/write. Keep read-only permissions for connections intended only for investigation.

Reading requires the relevant security-reader access. Updating incidents or alerts also requires the signed-in user's **Security Operator** or **Security Administrator** Microsoft Entra role, or an equivalent custom role, plus applicable Defender RBAC access. OAuth permission consent alone does not grant the user those roles.

Cases uses the same Graph audience/token connection as v1.0. Case Management permissions don't replace incident permissions needed for fallback or alert enrichment. Case visibility follows the tenant's applicable Defender/Sentinel RBAC and preview availability; this integration doesn't bypass those restrictions.

---

## Local Development

```bash
npm install
npm run build
PORT=3000 node dist/server.js
```

Cases-first is the default. To run the original incident implementation:

```bash
CASE_MANAGEMENT_ENABLED=false PORT=3000 node dist/server.js
```

`/health` reports `tools: 14`, `incidentStrategy` (`cases-first` or `incidents-only`), and `caseManagementPreview`.

Automated tests:

```bash
npm test
```

This builds the project and runs Node's built-in tests, including Cases reference resolution, tenant status families, 100-item page limits, safe ID handling, selective fallback, legacy-only regressions, asynchronous acceptance, and local HTTP MCP requests. All Graph calls are mocked. Docker builds run the same tests before producing the runtime image.

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
│   ├── caseManagement.ts  # Cases-first resolution, status handling, selective fallback
│   ├── toolRegistry.ts    # Tool registration and lookup
│   ├── updateValidation.ts # Shared validation for partial Graph updates
│   └── tools/
│       ├── index.ts       # Registers all tools
│       ├── incidents.ts   # ListIncidents, GetIncidentById, UpdateIncident
│       ├── alerts.ts      # ListAlerts, GetAlertById, UpdateAlert
│       ├── cases.ts       # Cases, references, statuses, UpdateCase
│       └── hunting.ts     # Tables overview, schema, RunHuntingQuery
├── test/
│   ├── tools.test.js      # Legacy contracts, validation, regressions, HTTP MCP
│   └── cases.test.js      # Cases-first contracts, fallback, async writes, HTTP MCP
├── infra/
│   └── azuredeploy.json   # ARM template for Deploy to Azure button
├── Dockerfile
├── package.json
├── tsconfig.json
└── .env.example
```

## License

MIT
