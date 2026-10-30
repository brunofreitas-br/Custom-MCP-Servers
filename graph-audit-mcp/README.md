# Microsoft Graph Audit MCP

Read-only, stateless MCP server for Microsoft Entra sign-in, directory audit, and risky-user investigations through Microsoft Graph v1.0.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fbrunofreitas-br%2FCustom-MCP-Servers%2Fmain%2Fgraph-audit-mcp%2Finfra%2Fazuredeploy.json)

The button deploys the public `ghcr.io/brunofreitas-br/graph-audit-mcp:latest` image to Azure Container Apps.

## Security model

- **Delegated token passthrough:** every `POST /mcp` request forwards that request's bearer token to Microsoft Graph.
- **No credentials or state:** the server stores no secrets, sessions, cache, or investigation data.
- **Read-only and v1.0-only:** all downstream calls are `GET` requests to `https://graph.microsoft.com/v1.0`.
- **Validated inputs:** tool arguments are allowlisted; IDs, timestamps, enums, page sizes, and continuation URLs are validated before use.
- Tokens are never written to responses or application logs.

## Tools

| Tool | Purpose | Arguments |
|---|---|---|
| `ListSignIns` | List sign-in records | `userId`, `appId`, `ipAddress`, `statusErrorCode`, `startDateTime`, `endDateTime`, `pageSize`, `maxPages` |
| `GetSignInById` | Get a sign-in record | `id` (required) |
| `ListDirectoryAudits` | List directory audit records | `activityDisplayName`, `category`, `result`, `initiatedByUserId`, `targetResourceId`, `startDateTime`, `endDateTime`, `pageSize`, `maxPages` |
| `GetDirectoryAuditById` | Get a directory audit record | `id` (required) |
| `ListRiskyUsers` | List risky users | `riskLevel`, `riskState`, `riskDetail`, `userId`, `pageSize`, `maxPages` |
| `GetRiskyUserById` | Get a risky user | `id` (required) |

List tools fetch one page by default. `pageSize` accepts 1–1000 and `maxPages` accepts 1–5. When the bound is reached and Graph has more results, the response preserves `@odata.nextLink`. Continuation links are followed only when they use HTTPS, `graph.microsoft.com`, v1.0, and the exact expected collection path.

## Microsoft Entra prerequisites

Create an app registration for the MCP client's OAuth connection and configure these **delegated** Microsoft Graph permissions:

| Data | Delegated permission |
|---|---|
| Sign-ins and directory audits | `AuditLog.Read.All` |
| Risky users | `IdentityRiskyUser.Read.All` |

Grant tenant admin consent. Microsoft Entra roles also apply to the signed-in user. Use a supported least-privileged role appropriate to the investigation, such as **Reports Reader**, **Security Reader**, **Security Operator**, **Security Administrator**, or **Global Reader**. Risk data access is licensing- and role-dependent; do not assume that admin consent alone grants every user visibility.

## Local development

Requires Node.js 20 or later.

```bash
npm install
npm test
npm start
```

Endpoints:

- MCP JSON-RPC: `POST http://localhost:3000/mcp`
- Health: `GET http://localhost:3000/health`

Example discovery request:

```bash
curl http://localhost:3000/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Tool calls require `Authorization: Bearer <delegated-user-token>`.

## Docker

The public image is built from `main` by GitHub Actions:

```bash
docker pull ghcr.io/brunofreitas-br/graph-audit-mcp:latest
docker run --rm -p 3000:3000 ghcr.io/brunofreitas-br/graph-audit-mcp:latest
```

To build it locally instead:

```bash
docker build -t graph-audit-mcp .
docker run --rm -p 3000:3000 graph-audit-mcp
```

The multi-stage image runs the build and test suite before producing a non-root Node.js 20 runtime image.

## Azure Container Apps

Use the **Deploy to Azure** button above, or deploy the ARM template with Azure CLI:

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file infra/azuredeploy.json
```

The template defaults to the public GHCR image, but `containerImage` can be overridden. It provisions Log Analytics, a Container Apps environment, an external HTTPS Container App, health probing, and scale-to-zero. It creates no app secrets because authentication remains token passthrough.

## Copilot Studio OAuth

1. In Microsoft Entra ID, register an application and add the delegated permissions above.
2. Grant admin consent and configure the redirect URI shown by the Copilot Studio connection.
3. In Copilot Studio, add a custom MCP server using `https://<container-app-fqdn>/mcp`.
4. Configure OAuth 2.0 with Microsoft Entra ID and Microsoft Graph delegated scopes. Use the tenant authorization and token endpoints required by your environment.
5. Authenticate the connection as a user with an appropriate Microsoft Entra role.
6. Confirm `tools/list`, then test each collection with a narrowly bounded query.

Do not configure client credentials or embed a secret in this server. The incoming user's token is the authorization boundary.

## Errors and diagnostics

Tool failures return MCP content with `isError: true`. Safe diagnostics include HTTP status, Graph request/client-request IDs, `Retry-After`, Graph error code, and permission or throttling guidance. Access tokens and upstream response bodies are excluded. HTTP 404 responses from this server identify incorrect local routes separately from Graph resource failures.
