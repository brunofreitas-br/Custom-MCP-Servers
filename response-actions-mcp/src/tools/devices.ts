import { registerTool } from "../toolRegistry.js";
import { apiRequest } from "../apiClient.js";

// ── Isolate Device ──────────────────────────────────────────────────────────
registerTool({
  name: "isolate_device",
  collection: "devices",
  description:
    "Isolates a device from the network via Microsoft Defender for Endpoint. Full = no network except Defender service; Selective = limited network.",
  inputSchema: {
    type: "object",
    properties: {
      machineId: { type: "string", description: "Defender for Endpoint machine ID" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
      isolationType: {
        type: "string",
        enum: ["Full", "Selective"],
        description: "Full = no network except Defender; Selective = limited network",
      },
    },
    required: ["machineId", "incidentId"],
  },
  handler: async (args, token) => {
    const machineId = args.machineId as string;
    const incidentId = args.incidentId as string;
    const isolationType = (args.isolationType as string) || "Full";
    const ts = new Date().toISOString();

    await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${machineId}/isolate`,
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
      result: "SUCCESS",
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
      machineId: { type: "string", description: "Defender for Endpoint machine ID" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["machineId", "incidentId"],
  },
  handler: async (args, token) => {
    const machineId = args.machineId as string;
    const incidentId = args.incidentId as string;
    const ts = new Date().toISOString();

    await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${machineId}/unisolate`,
      body: { Comment: `Released from isolation — Incident ${incidentId} — ${ts}` },
      token,
    });

    return {
      action: "unisolate_device",
      target: machineId,
      incidentId,
      timestamp: ts,
      result: "SUCCESS",
      message: `Device ${machineId} released from isolation.`,
    };
  },
});

// ── Run Antivirus Scan ──────────────────────────────────────────────────────
registerTool({
  name: "run_antivirus_scan",
  collection: "devices",
  description: "Triggers a Quick or Full antivirus scan on a device via Defender for Endpoint.",
  inputSchema: {
    type: "object",
    properties: {
      machineId: { type: "string", description: "Defender for Endpoint machine ID" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
      scanType: {
        type: "string",
        enum: ["Quick", "Full"],
        description: "Quick or Full antivirus scan",
      },
    },
    required: ["machineId", "incidentId"],
  },
  handler: async (args, token) => {
    const machineId = args.machineId as string;
    const incidentId = args.incidentId as string;
    const scanType = (args.scanType as string) || "Full";
    const ts = new Date().toISOString();

    await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${machineId}/runAntiVirusScan`,
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
      result: "SUCCESS",
      message: `${scanType} AV scan initiated on device ${machineId}.`,
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
      machineId: { type: "string", description: "Defender for Endpoint machine ID" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["machineId", "incidentId"],
  },
  handler: async (args, token) => {
    const machineId = args.machineId as string;
    const incidentId = args.incidentId as string;
    const ts = new Date().toISOString();

    await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${machineId}/restrictCodeExecution`,
      body: { Comment: `App restriction — Incident ${incidentId} — ${ts}` },
      token,
    });

    return {
      action: "restrict_app_execution",
      target: machineId,
      incidentId,
      timestamp: ts,
      result: "SUCCESS",
      message: `App execution restricted on device ${machineId}.`,
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
      machineId: { type: "string", description: "Defender for Endpoint machine ID" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["machineId", "incidentId"],
  },
  handler: async (args, token) => {
    const machineId = args.machineId as string;
    const incidentId = args.incidentId as string;
    const ts = new Date().toISOString();

    await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${machineId}/unrestrictCodeExecution`,
      body: { Comment: `Restriction removed — Incident ${incidentId} — ${ts}` },
      token,
    });

    return {
      action: "unrestrict_app_execution",
      target: machineId,
      incidentId,
      timestamp: ts,
      result: "SUCCESS",
      message: `App execution restriction removed from device ${machineId}.`,
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
      machineId: { type: "string", description: "Defender for Endpoint machine ID" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["machineId", "incidentId"],
  },
  handler: async (args, token) => {
    const machineId = args.machineId as string;
    const incidentId = args.incidentId as string;
    const ts = new Date().toISOString();

    await apiRequest({
      base: "defender",
      method: "POST",
      path: `/machines/${machineId}/collectInvestigationPackage`,
      body: { Comment: `Evidence collection — Incident ${incidentId} — ${ts}` },
      token,
    });

    return {
      action: "collect_investigation_package",
      target: machineId,
      incidentId,
      timestamp: ts,
      result: "SUCCESS",
      message: `Investigation package requested for device ${machineId}. Available in Defender portal when ready.`,
    };
  },
});
