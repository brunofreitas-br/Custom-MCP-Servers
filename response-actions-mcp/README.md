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

- **14 tools** — identity/device response actions, indicator blocking, file quarantine, hostname lookup, and action tracking
- **Token passthrough** — zero credentials stored server-side; each user's Bearer token is forwarded directly to Microsoft APIs
- **Fully stateless** — no sessions, no state, scales to zero on Azure Container Apps
- **Audit trail** — every write action requires an `incidentId` parameter for traceability; read-only lookups don't create actions
- **Trackable device actions** — scan, isolation, app restrictions, forensics, and quarantine return the Defender action ID and actual status instead of assuming completion

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
| 11 | `block_indicator` | Block URLs, domains, IPs, file hashes, or certificate thumbprints | Defender |
| 12 | `stop_and_quarantine_file` | Stop execution and quarantine a file on a device by SHA-1 | Defender |
| 13 | `find_machines` | Read-only hostname/FQDN lookup returning all matching accessible MDE machines | Defender |
| 14 | `get_machine_action` | Read the actual status of a previously submitted device action | Defender |

### MCP endpoints

| Endpoint | Tools | OAuth scope |
|----------|-------|-------------|
| `/mcp/identity` | 4 identity actions | `https://graph.microsoft.com/.default` |
| `/mcp/devices` | 10 Defender tools, including device lookup and action tracking | `https://api.securitycenter.microsoft.com/.default` |

The lookup/tracking tools reuse the existing Defender connection. There is no additional endpoint and no change to the identity connection.

## Finding devices and tracking response actions

Use `find_machines` before remediation when the request supplies only a hostname:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "find_machines",
    "arguments": { "hostname": "pc01.contoso.com" }
  }
}
```

- FQDN searches are exact. A short name such as `pc01` matches that exact first DNS label, not `pc010`.
- The response includes `resolution` (`UNIQUE`, `AMBIGUOUS`, or `NOT_FOUND`), `matchCount`, and `matches`. Each match preserves device metadata and exposes its MDE ID as `machineId`.
- Continuation pages are followed before declaring uniqueness. Unexpected/repeated continuation URLs or mismatched machine names fail explicitly.
- No machine is selected automatically. Even a unique visible match must be checked against the intended device, onboarding state, and `lastSeen`.
- Multiple domains, device re-onboarding, and stale records can yield more than one matching MDE ID. Do not simply choose the first/latest result.
- Visibility is limited by the caller's RBAC and Defender retention. Empty results don't prove the device doesn't exist; upstream 403/404 responses aren't converted into empty lists.
- Device actions still require an explicit `machineId`. Use the verified MDE ID (or alert evidence `mdeDeviceId`), not a hostname or an Entra `aadDeviceId`.

`find_machines` requires delegated `Machine.Read` or `Machine.ReadWrite`. It does not request a scan or any other mutation.

After an authorized scan, isolation, restriction, investigation-package, or quarantine request, preserve the returned `machineActionId` and query:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "get_machine_action",
    "arguments": { "actionId": "<MACHINE_ACTION_ID>" }
  }
}
```

This GET requires delegated **`Machine.ReadWrite`**, as documented for the native machine-action endpoint, even though this MCP tool itself is read-only. `Machine.Scan` alone does not authorize this status query. The tool does not automatically poll, resubmit, or cancel an action.

### Device-action results and compatibility

**Intentional contract change:** existing device actions no longer return unconditional `result: "SUCCESS"`. Their original target/incident/scope fields are retained, and the response now includes `machineActionId`, `status`, `completed`, `succeeded`, `machineAction` (the original Defender resource), and `nextStep`.

| Defender `status` | MCP `result` | `completed` | `succeeded` |
|-------------------|--------------|-------------|-------------|
| `Pending` | `REQUESTED` | false | null |
| `InProgress` | `IN_PROGRESS` | false | null |
| `Succeeded` | `SUCCEEDED` | true | true |
| `Failed` | `FAILED` | true | false |
| `TimeOut` | `TIMED_OUT` | true | false |
| `Cancelled` | `CANCELLED` | true | false |
| Unknown future value | `UNKNOWN` | null | null |

An HTTP success means the API returned a resource, not that remediation succeeded. Report success only when the returned action has `succeeded: true`. Missing/mismatched action responses fail explicitly; they never become completed success. Checking status is a new GET, not a repeat of the original POST.

Identity actions and indicator submission keep their existing result contracts. Case updates in the triage server continue to use their separate `ACCEPTED`/202 contract.

References: [List machines](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines), [Get MachineAction](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineaction-object), and [MachineAction statuses](https://learn.microsoft.com/en-us/defender-endpoint/api/machineaction).

## Operational errors and agent behavior

Tool execution failures preserve the existing JSON-RPC error envelope and add structured details under `error.data`:

```json
{
  "error": {
    "code": -32000,
    "message": "API request failed ...",
    "data": {
      "error": "API request failed ...",
      "diagnostics": {
        "code": "UPSTREAM_HTTP_ERROR",
        "tool": "get_machine_action",
        "target": { "actionId": "..." },
        "httpStatus": 403,
        "upstream": {
          "service": "defender",
          "method": "GET",
          "url": "https://api.securitycenter.microsoft.com/api/machineactions/...",
          "requestId": "...",
          "clientRequestId": "..."
        },
        "automaticRetryAllowed": false,
        "guidance": ["..."]
      }
    }
  }
}
```

HTTP diagnostics retain the upstream error code, request IDs, date and `Retry-After` when available. Network/read/JSON failures have distinct diagnostic codes. Access-token headers aren't serialized, and a token echoed in an upstream error body is redacted.

An unknown MCP route now returns HTTP 404 JSON with `MCP_ENDPOINT_NOT_FOUND` and the expected paths. This is different from a tool's downstream `UPSTREAM_HTTP_ERROR`/404. Check the connection URL before investigating an incident or machine through a connector that can't initialize.

Add these rules to the Orchestrator/Response Agent instructions and refresh the tool catalog after redeploying:

```text
- Resolve a hostname using find_machines. Never substitute an Entra ID, Case ID or Incident ID for an MDE machine ID.
- When matches are ambiguous, obtain the intended FQDN/MDE ID; never select the first device automatically.
- Verify the target and obtain authorization before remediation. Triage remains read-only.
- Preserve machineActionId. REQUESTED/IN_PROGRESS is not completion. Read progress using get_machine_action; never repeat a POST just to check status.
- Declare remediation success only for succeeded=true. Report Failed/TimeOut/Cancelled and unknown statuses accurately.
- Stop the affected operation on 401/403. Do not change tools, fields, IDs or API audiences to bypass it, and do not claim a specific missing role from a 403 alone.
- Preserve error.data diagnostics and correlation IDs. Do not expose access tokens. Respect Retry-After and the caller's retry policy.
- A network error after a write leaves its outcome uncertain; check Defender Action center before any retry.
```

## Blocking indicators

`block_indicator` submits or updates an indicator through Defender's `/api/indicators` API. It requires `indicatorType`, `indicatorValue`, `incidentId`, `title`, `description`, and an explicit `scope`.

| Indicator types | Action sent to Defender |
|-----------------|-------------------------|
| `Url`, `DomainName`, `IpAddress` | `Block` |
| `FileSha1`, `FileSha256`, `FileMd5` | `BlockAndRemediate` |
| `CertificateThumbprint` (SHA-1 thumbprint) | `BlockAndRemediate` |

File and certificate indicators therefore request remediation as well as blocking. Legacy `AlertAndBlock`/`Alert` actions are not used.

Scope must be chosen on every call:

- `scope: "deviceGroups"` requires a non-empty `rbacGroupNames` array.
- `scope: "allDevices"` explicitly applies across the tenant's managed devices. Do not supply `rbacGroupNames` with this scope.
- Omitting the scope, supplying empty device groups, or mixing the two modes is rejected. Confirm the intended scope before invoking the tool.

Optional fields are `expirationTime` (a future ISO 8601 timestamp with timezone), `severity` (`Informational`, `Low`, `Medium`, `High`), and `generateAlert` (boolean). Supply an expiration when the block must expire; the server does not invent one. Submitting an existing indicator can update its action, scope, and other supplied settings.

Example JSON-RPC request to block a URL for a device group:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "block_indicator",
    "arguments": {
      "indicatorType": "Url",
      "indicatorValue": "https://blocked.example/download",
      "incidentId": "SOC-123",
      "title": "Confirmed malicious URL",
      "description": "Block following incident investigation",
      "scope": "deviceGroups",
      "rbacGroupNames": ["SOC Lab"],
      "severity": "High",
      "generateAlert": true
    }
  }
}
```

The incident ID and request timestamp are appended to the indicator description for traceability. The result is `SUBMITTED`, with the returned Defender entity under `indicator`; it does not claim the block is already enforced.

Important prerequisites and limits:

- Network indicators require **Custom network indicators** to be enabled. SmartScreen and/or Network Protection in block mode must be configured as appropriate. HTTPS path-level blocking varies by browser.
- IP indicators are for individual external IP addresses, not internal addresses, CIDR blocks, or ranges. Domains must not include a scheme, path, port, or wildcard.
- File indicators require the **Allow or block file** feature and applicable Defender Antivirus/cloud-protection prerequisites. Certificate blocking also has Defender platform and certificate restrictions.
- Enforcement is asynchronous and subject to product prerequisites, device availability, RBAC, and conflicting policies.

References: [Submit or update indicator API](https://learn.microsoft.com/en-us/defender-endpoint/api/post-ti-indicator), [indicator actions](https://learn.microsoft.com/en-us/defender-endpoint/api/ti-indicator), [network indicators](https://learn.microsoft.com/en-us/defender-endpoint/indicator-ip-domain), [file indicators](https://learn.microsoft.com/en-us/defender-endpoint/indicator-file), and [certificate indicators](https://learn.microsoft.com/en-us/defender-endpoint/indicator-certificates).

## Stopping and quarantining files

`stop_and_quarantine_file` invokes Defender's native `StopAndQuarantineFile` action. It requires `machineId`, a 40-character hexadecimal `sha1`, and `incidentId`. An optional `comment` adds the analyst's justification to the action's audit comment.

This is **quarantine, not permanent deletion by file path**. It stops execution and removes the file through Defender's quarantine workflow on the specified device. It does not create a blocking indicator for other devices; use `block_indicator` separately if needed.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "stop_and_quarantine_file",
    "arguments": {
      "machineId": "<DEFENDER_MACHINE_ID>",
      "sha1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "incidentId": "SOC-123",
      "comment": "Confirmed malicious executable"
    }
  }
}
```

The result is `REQUESTED`, not completed success. The returned `machineAction` includes its ID and current status, such as `Pending`; track completion or failure in Microsoft Defender's Action center. This MCP does not poll the action to completion.

The API supports Windows 10 version 1703 or later and Windows 11, requires Defender Antivirus to be running at least in passive mode, and is subject to trusted-file restrictions. The signed-in user needs **Active remediation actions** permission and access to the device's group. See the [Stop and quarantine file API](https://learn.microsoft.com/en-us/defender-endpoint/api/stop-and-quarantine-file).

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
- `Ti.ReadWrite` — submit/update blocking indicators
- `Machine.StopAndQuarantine` — stop execution and quarantine a file
- `Machine.ReadWrite` — retrieve machine-action status; also covers machine lookup
- `Machine.Read` — optional least-privilege alternative for hostname lookup alone, without action tracking

Click **Grant admin consent**.

For an existing deployment, add delegated `Machine.ReadWrite` for action tracking (or `Machine.Read` for lookup only), grant admin consent, redeploy the updated image, and reconnect the Defender OAuth connection so it obtains a token with the new permissions. Refresh the MCP tool list and update consumers of the old device-action `SUCCESS` response. The existing URLs remain unchanged.

#### Create a client secret

1. Go to Certificates & secrets → New client secret
2. Copy the secret Value immediately

#### Note your IDs

From the Overview page, copy:
- Application (client) ID
- Directory (tenant) ID

### Step 2: Configure in Copilot Studio

Create **two MCP tools/connections**, one per API audience:

| Connection | Server URL | Scopes |
|------------|------------|--------|
| SOC Response - Identity | `https://<YOUR_CONTAINER_APP>.azurecontainerapps.io/mcp/identity` | `https://graph.microsoft.com/.default` |
| SOC Response - Devices and Indicators | `https://<YOUR_CONTAINER_APP>.azurecontainerapps.io/mcp/devices` | `https://api.securitycenter.microsoft.com/.default` |

For each connection:

1. Open your agent in [Copilot Studio](https://copilotstudio.microsoft.com/) → Tools → Add tool.
2. Click + New tool → select Model Context Protocol.
3. Use the name and URL from the table above, with **OAuth 2.0** authentication.
4. Select **Manual** and use:

| Field | Value |
|-------|-------|
| Client ID | Your Application (client) ID |
| Client secret | Your secret value |
| Authorization URL | `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize` |
| Token URL template | `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token` |
| Refresh URL | `https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token` |
| Scopes | The scope for this connection from the table above |

5. Click Create → copy the generated Redirect URI.

Both connections can use the same App Registration, but must obtain separate tokens for Graph and Defender. A Graph token cannot authorize the new Defender actions.

### Step 3: Add the Redirect URI

1. Azure Portal → your App Registration → Authentication
2. Add a platform → Web → paste the Redirect URI
3. Click Configure

### Step 4: Create the connection

1. Back in Copilot Studio → Next → Create new connection
2. Sign in with your Microsoft account
3. Green checkmark ✅ → Add and configure
4. Repeat for both connections and register each generated Redirect URI.
5. The identity connection exposes 4 tools and the Defender connection exposes 10, for 14 tools in total.

## How It Works

```
Copilot Studio / Any MCP Client
        │
        │  POST /mcp/identity or /mcp/devices
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
                POST /machines/{id}/isolate, StopAndQuarantineFile, etc.
                POST /indicators
```

⚠️ **Important**: The `/mcp/devices` endpoint uses the Defender for Endpoint API (`api.securitycenter.microsoft.com`), including indicator and quarantine actions. Its token must be obtained with `https://api.securitycenter.microsoft.com/.default`, not the Graph scope. Configure the two separate connections described above.

## Required Permissions

| Permission | Type | Purpose |
|------------|------|---------|
| `User.ReadWrite.All` | Delegated | Block/unblock user, reset password |
| `User.RevokeSessions.All` | Delegated | Revoke sign-in sessions |
| `Machine.Isolate` | Delegated | Isolate/unisolate device |
| `Machine.Scan` | Delegated | Run AV scan |
| `Machine.RestrictExecution` | Delegated | Restrict/unrestrict app execution |
| `Machine.CollectForensics` | Delegated | Collect investigation package |
| `Ti.ReadWrite` | Delegated | Submit/update blocking indicators |
| `Machine.StopAndQuarantine` | Delegated | Stop and quarantine a file on a device |
| `Machine.Read` | Delegated | Hostname/FQDN lookup only; optional if Machine.ReadWrite is granted |
| `Machine.ReadWrite` | Delegated | Retrieve machine-action status and perform machine lookup |

The signed-in user's Entra/Defender RBAC must also authorize the requested operation and device scope; consenting to an OAuth permission does not grant those roles. In particular, quarantine requires **Active remediation actions** and access to the target device. Indicator management requires the tenant's applicable indicator-management permissions.

Use delegated `Ti.ReadWrite`, not application-only `Ti.ReadWrite.All`, for this server's user-token passthrough model. Connections without the new permissions can continue using their previously authorized actions.

## Local Development

```bash
npm install
npm run build
PORT=3001 node dist/server.js
```

Automated tests:

```bash
npm test
```

This builds the project and runs Node's built-in tests for indicator types, scope, hostname resolution/ambiguity/pagination, device-action states, validation, structured errors, legacy payloads, and local HTTP MCP routing. All downstream API calls are mocked, so tests do not change any tenant resources. Docker builds run the same tests.

Test:
```bash
# Health check
curl http://localhost:3001/health

# List identity tools
curl -X POST http://localhost:3001/mcp/identity \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# List Defender tools, including indicators and quarantine
curl -X POST http://localhost:3001/mcp/devices \
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
│   ├── validation.ts      # Validation helpers for new response actions
│   ├── machineActions.ts  # Shared validation and actual asynchronous action outcomes
│   └── tools/
│       ├── index.ts       # Registers all tools
│       ├── identity.ts    # block_user, unblock_user, revoke_sessions, reset_password
│       ├── devices.ts     # Device containment, forensics, stop_and_quarantine_file
│       ├── deviceLookup.ts # find_machines and get_machine_action
│       └── indicators.ts  # block_indicator with explicit scope
├── test/
│   ├── tools.test.js      # Tool contracts, validation, regressions, HTTP MCP
│   └── operations.test.js # Hostnames, action states, diagnostics, HTTP MCP
├── infra/
│   └── azuredeploy.json   # ARM template for Deploy to Azure button
├── Dockerfile
├── package.json
├── tsconfig.json
└── .env.example
```

## License

MIT
