import { registerTool } from "../toolRegistry.js";
import { apiRequest } from "../apiClient.js";
import { requireHex, requireString, validateArguments } from "../validation.js";
import { machineActionResult } from "../machineActions.js";

// ── Isolate Device ──────────────────────────────────────────────────────────
registerTool({
  name: "isolate_device",
  collection: "devices",
  description:
    "Isolates a device from the network via Microsoft Defender for Endpoint. Full = no network except Defender service; Selective = limited network.",
  inputSchema: {
    type: "object",
    properties: {
      machineId: { type: "string", minLength: 1, description: "MDE machine ID; resolve a hostname using find_machines first, never use an Entra device ID" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
      isolationType: {
        type: "string",
        enum: ["Full", "Selective"],
        description: "Full = no network except Defender; Selective = limited network",
      },
    },
    required: ["machineId", "incidentId"],
    additionalProperties: false,
  },
  handler: async (args, token) => {
    validateArguments(args, ["machineId", "incidentId", "isolationType"]);
    const machineId = requireString(args.machineId, "machineId");
    const incidentId = requireString(args.incidentId, "incidentId");
    const isolationType = args.isolationType ?? "Full";
    if (isolationType !== "Full" && isolationType !== "Selective") throw new Error("isolationType must be Full or Selective");
    const ts = new Date().toISOString();

    const machineAction = await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${encodeURIComponent(machineId)}/isolate`,
      body: {
        Comment: `Isolated by SOC — Incident ${incidentId} — ${ts}`,
        IsolationType: isolationType,
      },
      token,
    });

    return {
      action: "isolate_device",
      target: machineId,
      incidentId,
      isolationType,
      timestamp: ts,
      ...machineActionResult(machineAction, { machineId, type: "Isolate" }),
      message: `Device ${machineId} isolation requested (${isolationType}).`,
      rollback: "Use unisolate_device with the same machineId.",
    };
  },
});

// ── Unisolate Device ────────────────────────────────────────────────────────
registerTool({
  name: "unisolate_device",
  collection: "devices",
  description: "Removes network isolation from a device, restoring normal connectivity.",
  inputSchema: {
    type: "object",
    properties: {
      machineId: { type: "string", minLength: 1, description: "MDE machine ID; resolve a hostname using find_machines first" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["machineId", "incidentId"],
    additionalProperties: false,
  },
  handler: async (args, token) => {
    validateArguments(args, ["machineId", "incidentId"]);
    const machineId = requireString(args.machineId, "machineId");
    const incidentId = requireString(args.incidentId, "incidentId");
    const ts = new Date().toISOString();

    const machineAction = await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${encodeURIComponent(machineId)}/unisolate`,
      body: { Comment: `Released from isolation — Incident ${incidentId} — ${ts}` },
      token,
    });

    return {
      action: "unisolate_device",
      target: machineId,
      incidentId,
      timestamp: ts,
      ...machineActionResult(machineAction, { machineId, type: "Unisolate" }),
      message: `Release from isolation submitted for ${machineId}. Check the returned action status for completion.`,
    };
  },
});

// ── Run Antivirus Scan ──────────────────────────────────────────────────────
registerTool({
  name: "run_antivirus_scan",
  collection: "devices",
  description: "Request a Quick or Full Defender antivirus scan on a verified MDE machine ID. Resolve hostnames using find_machines first. Returns machineActionId/status; use get_machine_action to track completion instead of resubmitting. Requires Machine.Scan",
  inputSchema: {
    type: "object",
    properties: {
      machineId: { type: "string", minLength: 1, description: "MDE machine ID from alert mdeDeviceId or find_machines, not an Entra device ID or hostname" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
      scanType: {
        type: "string",
        enum: ["Quick", "Full"],
        description: "Quick or Full antivirus scan",
      },
    },
    required: ["machineId", "incidentId"],
    additionalProperties: false,
  },
  handler: async (args, token) => {
    validateArguments(args, ["machineId", "incidentId", "scanType"]);
    const machineId = requireString(args.machineId, "machineId");
    const incidentId = requireString(args.incidentId, "incidentId");
    const scanType = args.scanType ?? "Full";
    if (scanType !== "Quick" && scanType !== "Full") throw new Error("scanType must be Quick or Full");
    const ts = new Date().toISOString();

    const machineAction = await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${encodeURIComponent(machineId)}/runAntiVirusScan`,
      body: {
        Comment: `AV scan — Incident ${incidentId} — ${ts}`,
        ScanType: scanType,
      },
      token,
    });

    return {
      action: "run_antivirus_scan",
      target: machineId,
      incidentId,
      scanType,
      timestamp: ts,
      ...machineActionResult(machineAction, { machineId, type: "RunAntiVirusScan" }),
      message: `${scanType} AV scan request submitted for ${machineId}. Check the returned action status for completion.`,
    };
  },
});

// ── Restrict App Execution ──────────────────────────────────────────────────
registerTool({
  name: "restrict_app_execution",
  collection: "devices",
  description:
    "Restricts execution of non-Microsoft-signed applications on the device via Defender for Endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      machineId: { type: "string", minLength: 1, description: "MDE machine ID; resolve a hostname using find_machines first" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["machineId", "incidentId"],
    additionalProperties: false,
  },
  handler: async (args, token) => {
    validateArguments(args, ["machineId", "incidentId"]);
    const machineId = requireString(args.machineId, "machineId");
    const incidentId = requireString(args.incidentId, "incidentId");
    const ts = new Date().toISOString();

    const machineAction = await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${encodeURIComponent(machineId)}/restrictCodeExecution`,
      body: { Comment: `App restriction — Incident ${incidentId} — ${ts}` },
      token,
    });

    return {
      action: "restrict_app_execution",
      target: machineId,
      incidentId,
      timestamp: ts,
      ...machineActionResult(machineAction, { machineId, type: "RestrictCodeExecution" }),
      message: `App restriction submitted for ${machineId}. Check the returned action status for completion.`,
      rollback: "Use unrestrict_app_execution with the same machineId.",
    };
  },
});

// ── Unrestrict App Execution ────────────────────────────────────────────────
registerTool({
  name: "unrestrict_app_execution",
  collection: "devices",
  description: "Removes the application execution restriction from a device.",
  inputSchema: {
    type: "object",
    properties: {
      machineId: { type: "string", minLength: 1, description: "MDE machine ID; resolve a hostname using find_machines first" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["machineId", "incidentId"],
    additionalProperties: false,
  },
  handler: async (args, token) => {
    validateArguments(args, ["machineId", "incidentId"]);
    const machineId = requireString(args.machineId, "machineId");
    const incidentId = requireString(args.incidentId, "incidentId");
    const ts = new Date().toISOString();

    const machineAction = await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${encodeURIComponent(machineId)}/unrestrictCodeExecution`,
      body: { Comment: `Restriction removed — Incident ${incidentId} — ${ts}` },
      token,
    });

    return {
      action: "unrestrict_app_execution",
      target: machineId,
      incidentId,
      timestamp: ts,
      ...machineActionResult(machineAction, { machineId, type: "UnrestrictCodeExecution" }),
      message: `App restriction removal submitted for ${machineId}. Check the returned action status for completion.`,
    };
  },
});

// ── Collect Investigation Package ───────────────────────────────────────────
registerTool({
  name: "collect_investigation_package",
  collection: "devices",
  description:
    "Collects a forensic investigation package from the device (processes, network, registry, etc.). The package will be available in the Defender portal when ready.",
  inputSchema: {
    type: "object",
    properties: {
      machineId: { type: "string", minLength: 1, description: "MDE machine ID; resolve a hostname using find_machines first" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["machineId", "incidentId"],
    additionalProperties: false,
  },
  handler: async (args, token) => {
    validateArguments(args, ["machineId", "incidentId"]);
    const machineId = requireString(args.machineId, "machineId");
    const incidentId = requireString(args.incidentId, "incidentId");
    const ts = new Date().toISOString();

    const machineAction = await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${encodeURIComponent(machineId)}/collectInvestigationPackage`,
      body: { Comment: `Evidence collection — Incident ${incidentId} — ${ts}` },
      token,
    });

    return {
      action: "collect_investigation_package",
      target: machineId,
      incidentId,
      timestamp: ts,
      ...machineActionResult(machineAction, { machineId, type: "CollectInvestigationPackage" }),
      message: `Investigation package requested for device ${machineId}. Available in Defender portal when ready.`,
    };
  },
});

registerTool({
  name: "stop_and_quarantine_file",
  collection: "devices",
  description:
    "Stop execution and quarantine a file on a specific Windows device using its SHA-1 hash. This is Defender quarantine, not permanent deletion by file path. Returns the asynchronous machine action for tracking. Requires Machine.StopAndQuarantine",
  inputSchema: {
    type: "object",
    properties: {
      machineId: { type: "string", minLength: 1, description: "Defender for Endpoint machine ID" },
      sha1: { type: "string", pattern: "^[a-fA-F0-9]{40}$", description: "SHA-1 hash of the file to stop and quarantine" },
      incidentId: { type: "string", minLength: 1, description: "Incident ID included in the action comment for audit" },
      comment: { type: "string", minLength: 1, description: "Optional reason for the quarantine request" },
    },
    required: ["machineId", "sha1", "incidentId"],
    additionalProperties: false,
  },
  handler: async (args, token) => {
    validateArguments(args, ["machineId", "sha1", "incidentId", "comment"]);
    const machineId = requireString(args.machineId, "machineId");
    const sha1 = requireHex(args.sha1, 40, "sha1");
    const incidentId = requireString(args.incidentId, "incidentId");
    const comment = args.comment === undefined ? undefined : requireString(args.comment, "comment");
    const timestamp = new Date().toISOString();

    const machineAction = await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${encodeURIComponent(machineId)}/StopAndQuarantineFile`,
      body: {
        Sha1: sha1,
        Comment: `Stop and quarantine file - Incident ${incidentId} - ${timestamp}${comment ? ` - ${comment}` : ""}`,
      },
      token,
    });

    return {
      action: "stop_and_quarantine_file",
      target: machineId,
      sha1,
      incidentId,
      timestamp,
      ...machineActionResult(machineAction, { machineId, type: "StopAndQuarantineFile" }),
      message: "Stop and quarantine requested. Track the returned machine action in Defender Action center; completion is not implied.",
    };
  },
});
