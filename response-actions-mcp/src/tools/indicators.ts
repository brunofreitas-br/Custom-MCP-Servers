import { isIP } from "node:net";
import { registerTool } from "../toolRegistry.js";
import { apiRequest } from "../apiClient.js";
import { requireHex, requireString, validateArguments } from "../validation.js";

const hashLengths: Record<string, number> = {
  FileSha1: 40,
  FileSha256: 64,
  FileMd5: 32,
  CertificateThumbprint: 40,
};
const indicatorTypes = [...Object.keys(hashLengths), "IpAddress", "DomainName", "Url"];
const severities = ["Informational", "Low", "Medium", "High"];

const properties = {
  indicatorType: {
    type: "string",
    enum: indicatorTypes,
    description: "URLs, domains and IPs use Block; file hashes and certificate thumbprints use BlockAndRemediate",
  },
  indicatorValue: {
    type: "string",
    minLength: 1,
    description: "HTTP(S) URL, ASCII domain, single external IP (no CIDR), file hash, or SHA-1 certificate thumbprint",
  },
  incidentId: { type: "string", minLength: 1, description: "Incident ID included in the indicator description for audit" },
  title: { type: "string", minLength: 1, description: "Title for the blocking indicator" },
  description: { type: "string", minLength: 1, description: "Reason for blocking this indicator" },
  scope: {
    type: "string",
    enum: ["deviceGroups", "allDevices"],
    description: "Required explicit scope. allDevices applies across the tenant; deviceGroups requires rbacGroupNames",
  },
  rbacGroupNames: {
    type: "array",
    items: { type: "string", minLength: 1 },
    minItems: 1,
    description: "Non-empty list of device group names. Only provide with scope deviceGroups",
  },
  expirationTime: {
    type: "string",
    format: "date-time",
    description: "Optional future ISO 8601 timestamp with timezone. Supply this when the block must expire",
  },
  severity: { type: "string", enum: severities, description: "Indicator severity" },
  generateAlert: { type: "boolean", description: "Whether Defender should generate alerts for this indicator" },
};

function validateIndicatorValue(type: string, value: string): void {
  if (Object.hasOwn(hashLengths, type)) {
    requireHex(value, hashLengths[type], "indicatorValue");
  } else if (type === "IpAddress") {
    if (isIP(value) === 0) {
      throw new Error("indicatorValue must be a single IP address, not a CIDR range");
    }
  } else if (type === "DomainName") {
    const labels = value.split(".");
    if (value.length > 253 || labels.length < 2 || isIP(value) !== 0 ||
        labels.some((label) => !/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label))) {
      throw new Error("indicatorValue must be an ASCII domain without a scheme, path, port, or wildcard");
    }
  } else if (type === "Url") {
    if (!URL.canParse(value) || /\s/.test(value)) {
      throw new Error("indicatorValue must be a valid HTTP(S) URL");
    }
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || !url.hostname || url.username || url.password) {
      throw new Error("indicatorValue must be an HTTP(S) URL without embedded credentials");
    }
  }
}

registerTool({
  name: "block_indicator",
  collection: "devices",
  description:
    "Submit or update a blocking Defender indicator for a URL, domain, IP, file hash, or certificate. Explicit device-group or tenant-wide scope is required. File/certificate indicators also remediate. Submission does not mean enforcement has completed. Requires Ti.ReadWrite",
  inputSchema: {
    type: "object",
    properties,
    required: ["indicatorType", "indicatorValue", "incidentId", "title", "description", "scope"],
    additionalProperties: false,
  },
  handler: async (args, token) => {
    validateArguments(args, Object.keys(properties));
    const indicatorType = requireString(args.indicatorType, "indicatorType");
    if (!indicatorTypes.includes(indicatorType)) {
      throw new Error(`indicatorType must be one of: ${indicatorTypes.join(", ")}`);
    }
    const indicatorValue = requireString(args.indicatorValue, "indicatorValue");
    validateIndicatorValue(indicatorType, indicatorValue);
    const incidentId = requireString(args.incidentId, "incidentId");
    const title = requireString(args.title, "title");
    const description = requireString(args.description, "description");
    const scope = requireString(args.scope, "scope");

    let rbacGroupNames: string[];
    if (scope === "allDevices") {
      if (args.rbacGroupNames !== undefined) {
        throw new Error("Do not provide rbacGroupNames with scope allDevices");
      }
      rbacGroupNames = [];
    } else if (scope === "deviceGroups") {
      if (!Array.isArray(args.rbacGroupNames) || args.rbacGroupNames.length === 0) {
        throw new Error("scope deviceGroups requires a non-empty rbacGroupNames array");
      }
      rbacGroupNames = args.rbacGroupNames.map((name) => requireString(name, "rbacGroupNames item"));
    } else {
      throw new Error("scope must be deviceGroups or allDevices");
    }

    const timestamp = new Date().toISOString();
    const body: Record<string, unknown> = {
      indicatorType,
      indicatorValue,
      action: Object.hasOwn(hashLengths, indicatorType) ? "BlockAndRemediate" : "Block",
      title,
      description: `${description}\nIncident: ${incidentId}\nRequested at: ${timestamp}`,
      rbacGroupNames,
    };
    if (args.expirationTime !== undefined) {
      const expiration = requireString(args.expirationTime, "expirationTime");
      const time = Date.parse(expiration);
      if (!/^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(expiration) ||
          !Number.isFinite(time) || time <= Date.now()) {
        throw new Error("expirationTime must be a future ISO 8601 timestamp with timezone");
      }
      const [year, month, day] = expiration.slice(0, 10).split("-").map(Number);
      if (new Date(Date.UTC(year, month - 1, day)).toISOString().slice(0, 10) !== expiration.slice(0, 10)) {
        throw new Error("expirationTime must contain a valid calendar date");
      }
      body.expirationTime = expiration;
    }
    if (args.severity !== undefined) {
      const severity = requireString(args.severity, "severity");
      if (!severities.includes(severity)) {
        throw new Error(`severity must be one of: ${severities.join(", ")}`);
      }
      body.severity = severity;
    }
    if (args.generateAlert !== undefined) {
      if (typeof args.generateAlert !== "boolean") {
        throw new Error("generateAlert must be a boolean");
      }
      body.generateAlert = args.generateAlert;
    }

    const indicator = await apiRequest({ base: "defender", method: "POST", path: "/indicators", body, token });
    if (typeof indicator !== "object" || indicator === null ||
        !("id" in indicator) || typeof indicator.id !== "string" || indicator.id.trim().length === 0) {
      throw new Error("Defender returned an invalid indicator response. Check the indicator in Defender before retrying.");
    }
    return {
      action: "block_indicator",
      indicatorType,
      indicatorValue,
      incidentId,
      scope,
      timestamp,
      result: "SUBMITTED",
      message: "Blocking indicator submitted to Defender. Enforcement is asynchronous and depends on endpoint prerequisites.",
      indicator,
    };
  },
});
