import { registerTool } from "../toolRegistry.js";
import { apiRequest } from "../apiClient.js";

// ── Block User ──────────────────────────────────────────────────────────────
registerTool({
  name: "block_user",
  collection: "identity",
  description:
    "Disables sign-in for a user in Microsoft Entra ID. The user will be immediately unable to authenticate. Requires incidentId for audit trail.",
  inputSchema: {
    type: "object",
    properties: {
      userId: { type: "string", description: "UPN or Object ID of the user to disable" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["userId", "incidentId"],
  },
  handler: async (args, token) => {
    const userId = args.userId as string;
    const incidentId = args.incidentId as string;

    await apiRequest({
      base: "graph",
      method: "PATCH",
      path: `/users/${encodeURIComponent(userId)}`,
      body: { accountEnabled: false },
      token,
    });

    const ts = new Date().toISOString();
    return {
      action: "block_user",
      target: userId,
      incidentId,
      timestamp: ts,
      result: "SUCCESS",
      message: `User ${userId} has been DISABLED.`,
      rollback: "Use unblock_user with the same userId.",
    };
  },
});

// ── Unblock User ────────────────────────────────────────────────────────────
registerTool({
  name: "unblock_user",
  collection: "identity",
  description: "Re-enables sign-in for a previously blocked user in Microsoft Entra ID.",
  inputSchema: {
    type: "object",
    properties: {
      userId: { type: "string", description: "UPN or Object ID of the user to re-enable" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["userId", "incidentId"],
  },
  handler: async (args, token) => {
    const userId = args.userId as string;
    const incidentId = args.incidentId as string;

    await apiRequest({
      base: "graph",
      method: "PATCH",
      path: `/users/${encodeURIComponent(userId)}`,
      body: { accountEnabled: true },
      token,
    });

    const ts = new Date().toISOString();
    return {
      action: "unblock_user",
      target: userId,
      incidentId,
      timestamp: ts,
      result: "SUCCESS",
      message: `User ${userId} has been RE-ENABLED.`,
    };
  },
});

// ── Revoke Sessions ─────────────────────────────────────────────────────────
registerTool({
  name: "revoke_sessions",
  collection: "identity",
  description:
    "Invalidates all refresh tokens for the user, forcing re-authentication on all devices and applications.",
  inputSchema: {
    type: "object",
    properties: {
      userId: { type: "string", description: "UPN or Object ID of the user" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["userId", "incidentId"],
  },
  handler: async (args, token) => {
    const userId = args.userId as string;
    const incidentId = args.incidentId as string;

    await apiRequest({
      base: "graph",
      method: "POST",
      path: `/users/${encodeURIComponent(userId)}/revokeSignInSessions`,
      token,
    });

    const ts = new Date().toISOString();
    return {
      action: "revoke_sessions",
      target: userId,
      incidentId,
      timestamp: ts,
      result: "SUCCESS",
      message: `All sessions revoked for ${userId}. User must re-authenticate on all devices.`,
    };
  },
});

// ── Reset User Password ─────────────────────────────────────────────────────
registerTool({
  name: "reset_user_password",
  collection: "identity",
  description:
    "Resets the user's password to a random value and forces change at next sign-in. Share the temporary password via a secure channel only.",
  inputSchema: {
    type: "object",
    properties: {
      userId: { type: "string", description: "UPN or Object ID of the user" },
      incidentId: { type: "string", description: "Incident ID for audit trail" },
    },
    required: ["userId", "incidentId"],
  },
  handler: async (args, token) => {
    const userId = args.userId as string;
    const incidentId = args.incidentId as string;

    const tempPassword = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map((b) => String.fromCharCode(33 + (b % 93)))
      .join("");

    await apiRequest({
      base: "graph",
      method: "PATCH",
      path: `/users/${encodeURIComponent(userId)}`,
      body: {
        passwordProfile: {
          password: tempPassword,
          forceChangePasswordNextSignIn: true,
        },
      },
      token,
    });

    const ts = new Date().toISOString();
    return {
      action: "reset_user_password",
      target: userId,
      incidentId,
      timestamp: ts,
      result: "SUCCESS",
      message: `Password reset for ${userId}. User must change password at next sign-in.`,
      warning: "Temporary password generated — share via secure channel only.",
    };
  },
});
