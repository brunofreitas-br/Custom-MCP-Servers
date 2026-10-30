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

## Connect to Copilot Studio

The server uses Copilot Studio's **Streamable MCP** connection with a delegated Microsoft Graph token. Complete the following steps for each customer tenant.

### 1. Deploy the server

1. Select **Deploy to Azure** at the top of this README.
2. Choose the customer's subscription, resource group, region, and a globally unique Container App name.
3. Keep the default public image unless you intentionally publish your own build.
4. After the deployment completes, open the deployment **Outputs** and copy `mcpEndpoint`. It has this format:

   ```text
   https://<container-app-name>.<region>.azurecontainerapps.io/mcp
   ```

5. Open `https://<container-app-fqdn>/health` and confirm that it returns `"status": "ok"`.

### 2. Create the Microsoft Entra app registration

1. In the customer's Microsoft Entra admin center, go to **Identity** > **Applications** > **App registrations** > **New registration**.
2. Enter a recognizable name such as `Graph Audit MCP - Copilot Studio`.
3. For a customer-specific deployment, select **Accounts in this organizational directory only**.
4. Select **Register**, then record:
   - **Application (client) ID**
   - **Directory (tenant) ID**
5. Go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Delegated permissions** and add:
   - `AuditLog.Read.All`
   - `IdentityRiskyUser.Read.All`
6. Select **Grant admin consent** for the tenant.
7. Go to **Certificates & secrets** > **Client secrets** > **New client secret**. Copy the secret **value** immediately.

The client secret is stored in the Copilot Studio connection. Do not add it to this server, the ARM template, or the Container App.

### 3. Add the MCP server in Copilot Studio

1. Open the agent in Copilot Studio and make sure **generative orchestration** is enabled.
2. Go to **Tools** > **Add a tool** > **New tool** > **Model Context Protocol**.
3. Configure the basic server details:

   | Field | Value |
   |---|---|
   | Server name | `Microsoft Graph Audit MCP` |
   | Server description | `Read-only investigation of Microsoft Entra sign-ins, directory audits, and risky users.` |
   | Server URL | The `mcpEndpoint` deployment output |
   | Authentication | `OAuth 2.0` |
   | OAuth type | `Manual` |

4. Configure OAuth using the tenant and app registration created above:

   | Field | Value |
   |---|---|
   | Client ID | Application (client) ID |
   | Client secret | Client secret value |
   | Authorization URL | `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize` |
   | Token URL template | `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token` |
   | Refresh URL | `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token` |
   | Scopes | `openid profile offline_access https://graph.microsoft.com/AuditLog.Read.All https://graph.microsoft.com/IdentityRiskyUser.Read.All` |

5. Select **Create**. Copilot Studio displays a callback URL.
6. Copy that callback URL. In the Entra app registration, go to **Authentication** > **Add a platform** > **Web**, add the callback URL as a redirect URI, and save.
7. Return to Copilot Studio and select **Next**.
8. Select **Create a new connection**, sign in as an authorized user, and consent if prompted.
9. Select **Add to agent**.

Copilot Studio should discover all six tools automatically. If only some tools are needed, open the MCP tool settings, turn off **Allow all**, and enable the desired tools individually.

### 4. Test the connection

The signed-in user must have a supported Microsoft Entra role in addition to the delegated Graph permissions. Test with prompts such as:

- `Liste os últimos 10 sign-ins deste tenant.`
- `Mostre auditorias de diretório das últimas 24 horas.`
- `Liste usuários com nível de risco alto, limitando a resposta a uma página.`

Confirm that the activity map shows the corresponding MCP tool call and that the result contains Graph data rather than an authorization error.

### Troubleshooting

| Symptom | Check |
|---|---|
| MCP server can't be created | Confirm the URL ends in `/mcp`, uses HTTPS, and the Container App is reachable externally. |
| Sign-in or consent fails | Confirm the tenant ID, client ID, secret value, callback redirect URI, and space-separated scopes. |
| Graph returns HTTP 401 | Recreate the connection and verify that the access token targets Microsoft Graph. |
| Graph returns HTTP 403 | Verify admin consent, delegated permissions, the signed-in user's Entra role, licensing, and access policies. |
| Tools don't appear | Confirm generative orchestration is enabled, reconnect the MCP server, and check Power Platform data policies. |
| Risky users are unavailable | Confirm `IdentityRiskyUser.Read.All`, an eligible Entra role, and the required Microsoft Entra ID Protection licensing. |

Do not use client credentials or place an application token in the Container App. The incoming user's delegated Microsoft Graph token is the authorization boundary.

Official references:

- [Connect an existing MCP server to Copilot Studio](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-existing-server-to-agent)
- [Add MCP tools and resources to an agent](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-components-to-agent)
- [Troubleshoot MCP integration](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-troubleshooting)

## Errors and diagnostics

Tool failures return MCP content with `isError: true`. Safe diagnostics include HTTP status, Graph request/client-request IDs, `Retry-After`, Graph error code, and permission or throttling guidance. Access tokens and upstream response bodies are excluded. HTTP 404 responses from this server identify incorrect local routes separately from Graph resource failures.
