import { isIP } from "node:net";
import { apiRequest, defenderNextPage } from "../apiClient.js";
import { machineActionResult } from "../machineActions.js";
import { registerTool } from "../toolRegistry.js";
import { requireRecord, requireString, validateArguments } from "../validation.js";

registerTool({
  name: "find_machines",
  collection: "devices",
  description: "Read-only lookup of MDE machines by exact hostname or FQDN. A short hostname matches the same first DNS label, not arbitrary prefixes. Returns all accessible matches and explicitly marks ambiguity; never selects or remediates a device. Requires delegated Machine.Read or Machine.ReadWrite",
  inputSchema: {
    type: "object",
    properties: { hostname: { type: "string", minLength: 1, description: "Exact ASCII hostname or FQDN; not an Entra device ID, IP, URL, or wildcard" } },
    required: ["hostname"],
    additionalProperties: false,
  },
  handler: async (args, token) => {
    validateArguments(args, ["hostname"]);
    const hostname = requireString(args.hostname, "hostname").toLowerCase().replace(/\.$/, "");
    if (hostname.length > 253 || isIP(hostname) !== 0 ||
        hostname.split(".").some((label) => !/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(label))) {
      throw new Error("hostname must be an ASCII hostname or FQDN without a scheme, port, path, or wildcard");
    }
    const fqdn = hostname.includes(".");
    const filter = fqdn ? `computerDnsName eq '${hostname}'`
      : `(computerDnsName eq '${hostname}' or startswith(computerDnsName,'${hostname}.'))`;
    let page = await apiRequest({
      base: "defender", method: "GET", path: "/machines", token,
      params: { "$filter": filter, "$top": "100" },
    });
    const matches = new Map<string, Record<string, unknown>>();
    const visited = new Set<string>();
    while (true) {
      const collection = requireRecord(page, "Defender machines response");
      if (!Array.isArray(collection.value)) throw new Error("Defender machines response is missing the value array");
      for (const value of collection.value) {
        const machine = requireRecord(value, "Defender machine");
        const machineId = requireString(machine.id, "MDE machine ID");
        const name = requireString(machine.computerDnsName, "computerDnsName").toLowerCase().replace(/\.$/, "");
        if ((fqdn && name !== hostname) || (!fqdn && name !== hostname && !name.startsWith(`${hostname}.`))) {
          throw new Error("Defender returned a machine outside the requested hostname; no target was selected");
        }
        matches.set(machineId, { ...machine, machineId });
      }
      if (collection["@odata.nextLink"] === undefined) break;
      const nextLink = requireString(collection["@odata.nextLink"], "@odata.nextLink");
      if (visited.has(nextLink)) throw new Error("Defender returned a repeated pagination URL");
      visited.add(nextLink);
      page = await defenderNextPage(nextLink, "/machines", token);
    }
    return {
      hostname,
      resolution: matches.size === 0 ? "NOT_FOUND" : matches.size === 1 ? "UNIQUE" : "AMBIGUOUS",
      matchCount: matches.size,
      matches: [...matches.values()],
      scope: "Devices visible to the authenticated user within Defender retention and RBAC scope.",
      message: matches.size === 0 ? "No visible match was returned. This does not prove the device does not exist."
        : matches.size === 1 ? "One visible match. Verify its identity, onboarding status and lastSeen before authorizing any action."
          : "Multiple machines match. Resolve the intended FQDN/MDE machine ID before any device action; do not pick the first.",
    };
  },
});

registerTool({
  name: "get_machine_action",
  collection: "devices",
  description: "Read the actual status of a previously submitted Defender machine action by actionId. Does not resubmit, cancel or automatically poll the action. Requires delegated Machine.ReadWrite",
  inputSchema: {
    type: "object",
    properties: { actionId: { type: "string", minLength: 1, description: "machineActionId returned by scan, isolation, quarantine or another Defender action; not a machine ID" } },
    required: ["actionId"],
    additionalProperties: false,
  },
  handler: async (args, token) => {
    validateArguments(args, ["actionId"]);
    const actionId = requireString(args.actionId, "actionId");
    const resource = await apiRequest({
      base: "defender", method: "GET", path: `/machineactions/${encodeURIComponent(actionId)}`, token,
    });
    return { action: "get_machine_action", ...machineActionResult(resource, { actionId }) };
  },
});
