import { requireRecord, requireString } from "./validation.js";

export function machineActionResult(value: unknown, expected: { machineId?: string; actionId?: string; type?: string } = {}) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Defender returned an invalid machine action response. Check the Action center before retrying.");
  }
  const resource = requireRecord(value, "Defender machine action response");
  if (typeof resource.id !== "string" || !resource.id.trim() ||
      typeof resource.status !== "string" || !resource.status.trim()) {
    throw new Error("Defender returned an invalid machine action response. Check the Action center before retrying.");
  }
  const id = requireString(resource.id, "Machine action ID");
  const status = requireString(resource.status, "Machine action status");
  if ((expected.machineId && resource.machineId !== undefined && resource.machineId !== expected.machineId) ||
      (expected.actionId && id !== expected.actionId) ||
      (expected.type && resource.type !== undefined && resource.type !== expected.type)) {
    throw new Error("Defender returned a different machine action or target. Check the Action center before retrying.");
  }
  const results: Record<string, string> = {
    Pending: "REQUESTED",
    InProgress: "IN_PROGRESS",
    Succeeded: "SUCCEEDED",
    Failed: "FAILED",
    TimeOut: "TIMED_OUT",
    Cancelled: "CANCELLED",
  };
  const completed = ["Succeeded", "Failed", "TimeOut", "Cancelled"].includes(status);
  return {
    result: Object.hasOwn(results, status) ? results[status] : "UNKNOWN",
    machineActionId: id,
    status,
    completed: Object.hasOwn(results, status) ? completed : null,
    succeeded: completed ? status === "Succeeded" : null,
    machineAction: resource,
    nextStep: completed ? "Report the returned outcome. Do not automatically repeat this action."
      : "Use get_machine_action with machineActionId to read progress. Do not resubmit the original action.",
  };
}
