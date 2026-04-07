/**
 * Token Vault — Encrypted OAuth Token Storage & Agent Access Control
 *
 * Manages OAuth connections (Google, GitHub, Slack, etc.) via Auth0,
 * stores tokens encrypted at rest (AES-256-GCM), and provides
 * scoped agent access with approval workflows and audit logging.
 *
 * Firestore collections:
 *   tokenVaultConnections — encrypted OAuth tokens per org
 *   tokenVaultRequests    — agent access requests (pending/approved/denied)
 *   tokenVaultAuditLog    — immutable audit trail for all token operations
 */

import { db } from "./firebase";
import {
  collection,
  doc,
  addDoc,
  getDoc,
  getDocs,
  updateDoc,
  deleteDoc,
  query,
  where,
  orderBy,
  limit as firestoreLimit,
  serverTimestamp,
  Timestamp,
} from "firebase/firestore";
import { encryptValue, decryptValue, maskValue } from "./secrets";

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/** Supported OAuth providers via Auth0 */
export type OAuthProvider = "google" | "github" | "slack" | "microsoft" | "discord";

/** Provider display metadata */
export const PROVIDER_CONFIG: Record<OAuthProvider, {
  label: string;
  icon: string;
  color: string;
  auth0Connection: string;
  defaultScopes: string[];
  availableScopes: { id: string; label: string; description: string; risk: "low" | "medium" | "high" }[];
}> = {
  google: {
    label: "Google",
    icon: "G",
    color: "#4285f4",
    auth0Connection: "google-oauth2",
    defaultScopes: ["openid", "email", "profile"],
    availableScopes: [
      { id: "email", label: "Email (read)", description: "Read email messages and metadata", risk: "medium" },
      { id: "gmail.send", label: "Email (send)", description: "Send emails on behalf of user", risk: "high" },
      { id: "calendar.readonly", label: "Calendar (read)", description: "View calendar events", risk: "low" },
      { id: "calendar.events", label: "Calendar (write)", description: "Create and edit calendar events", risk: "medium" },
      { id: "drive.readonly", label: "Drive (read)", description: "View files in Google Drive", risk: "low" },
      { id: "drive.file", label: "Drive (write)", description: "Create and edit files in Drive", risk: "medium" },
      { id: "sheets", label: "Sheets", description: "Read and write Google Sheets", risk: "medium" },
    ],
  },
  github: {
    label: "GitHub",
    icon: "GH",
    color: "#333",
    auth0Connection: "github",
    defaultScopes: ["openid", "profile"],
    availableScopes: [
      { id: "repo", label: "Repositories", description: "Full access to public and private repos", risk: "high" },
      { id: "repo:status", label: "Repo status", description: "Read commit status", risk: "low" },
      { id: "read:org", label: "Orgs (read)", description: "Read org membership", risk: "low" },
      { id: "gist", label: "Gists", description: "Create and edit gists", risk: "medium" },
      { id: "read:user", label: "Profile (read)", description: "Read user profile info", risk: "low" },
      { id: "workflow", label: "Actions", description: "Trigger and manage GitHub Actions", risk: "high" },
    ],
  },
  slack: {
    label: "Slack",
    icon: "S",
    color: "#4a154b",
    auth0Connection: "slack",
    defaultScopes: ["openid", "profile"],
    availableScopes: [
      { id: "channels:read", label: "Channels (read)", description: "View channel list and info", risk: "low" },
      { id: "chat:write", label: "Messages (send)", description: "Send messages to channels", risk: "medium" },
      { id: "files:read", label: "Files (read)", description: "View shared files", risk: "low" },
      { id: "files:write", label: "Files (upload)", description: "Upload and share files", risk: "medium" },
      { id: "users:read", label: "Users (read)", description: "View workspace members", risk: "low" },
      { id: "reactions:write", label: "Reactions", description: "Add emoji reactions", risk: "low" },
    ],
  },
  microsoft: {
    label: "Microsoft",
    icon: "MS",
    color: "#00a4ef",
    auth0Connection: "windowslive",
    defaultScopes: ["openid", "email", "profile"],
    availableScopes: [
      { id: "Mail.Read", label: "Mail (read)", description: "Read Outlook emails", risk: "medium" },
      { id: "Mail.Send", label: "Mail (send)", description: "Send Outlook emails", risk: "high" },
      { id: "Calendars.ReadWrite", label: "Calendar", description: "Read and write calendar", risk: "medium" },
      { id: "Files.ReadWrite", label: "OneDrive", description: "Read and write OneDrive files", risk: "medium" },
      { id: "Team.ReadBasic.All", label: "Teams (read)", description: "Read Teams channels", risk: "low" },
    ],
  },
  discord: {
    label: "Discord",
    icon: "D",
    color: "#5865f2",
    auth0Connection: "discord",
    defaultScopes: ["identify"],
    availableScopes: [
      { id: "guilds", label: "Servers", description: "View server list", risk: "low" },
      { id: "guilds.members.read", label: "Members", description: "View server members", risk: "low" },
      { id: "messages.read", label: "Messages (read)", description: "Read message content", risk: "medium" },
      { id: "bot", label: "Bot actions", description: "Perform bot actions in servers", risk: "high" },
    ],
  },
};

/** A stored OAuth connection (tokens encrypted at rest) */
export interface TokenVaultConnection {
  id: string;
  orgId: string;
  provider: OAuthProvider;
  /** Auth0 user sub (e.g., "google-oauth2|123456") */
  auth0Sub: string;
  /** Display name from the provider profile */
  displayName: string;
  /** Email associated with the connection */
  email: string;
  /** Encrypted access token */
  encryptedAccessToken: string;
  /** Encrypted refresh token (if available) */
  encryptedRefreshToken?: string;
  /** IV for access token decryption */
  accessTokenIv: string;
  /** IV for refresh token decryption */
  refreshTokenIv?: string;
  /** Masked preview of the access token */
  maskedAccessToken: string;
  /** Scopes granted by the OAuth provider */
  grantedScopes: string[];
  /** Token expiry (null if non-expiring) */
  expiresAt: Date | null;
  /** Connection metadata */
  connectedBy: string;
  connectedAt: Date | null;
  lastUsedAt: Date | null;
  usageCount: number;
  /** Whether this connection is still active */
  active: boolean;
}

/** An agent's request for token access */
export interface TokenVaultRequest {
  id: string;
  orgId: string;
  agentId: string;
  agentName: string;
  connectionId: string;
  provider: OAuthProvider;
  /** Specific scopes the agent is requesting */
  requestedScopes: string[];
  /** Why the agent needs access */
  reason: string;
  /** Risk level (auto-calculated from scope risk) */
  riskLevel: "low" | "medium" | "high";
  /** Request status */
  status: "pending" | "approved" | "denied" | "revoked" | "expired";
  /** Who reviewed the request */
  reviewedBy?: string;
  reviewedAt?: Date | null;
  reviewNote?: string;
  /** Expiry for the approval (optional) */
  approvalExpiresAt?: Date | null;
  /** Auto-approve if all scopes are low-risk */
  autoApproved: boolean;
  createdAt: Date | null;
}

/** Audit log entry for all token operations */
export interface TokenVaultAuditEntry {
  id: string;
  orgId: string;
  action: "connect" | "disconnect" | "request" | "approve" | "deny" | "revoke" | "token_use" | "token_refresh" | "auto_approve";
  provider?: OAuthProvider;
  connectionId?: string;
  agentId?: string;
  agentName?: string;
  requestId?: string;
  /** Scopes involved in this action */
  scopes?: string[];
  /** Who performed the action (wallet or agent ID) */
  actorId: string;
  actorType: "user" | "agent" | "system";
  /** Human-readable description */
  description: string;
  /** Extra metadata */
  metadata?: Record<string, unknown>;
  timestamp: Date | null;
}

// ═══════════════════════════════════════════════════════════════
// Connection CRUD
// ═══════════════════════════════════════════════════════════════

/** Store a new OAuth connection with encrypted tokens */
export async function storeConnection(
  orgId: string,
  provider: OAuthProvider,
  tokenData: {
    auth0Sub: string;
    displayName: string;
    email: string;
    accessToken: string;
    refreshToken?: string;
    grantedScopes: string[];
    expiresIn?: number;
  },
  connectedBy: string,
): Promise<string> {
  const masterSecret = process.env.SECRETS_MASTER_KEY || process.env.NEXTAUTH_SECRET || "swarm-vault-default";

  const { encryptedValue: encAccessToken, iv: accessIv } = encryptValue(tokenData.accessToken, orgId, masterSecret);
  let encRefreshToken: string | undefined;
  let refreshIv: string | undefined;
  if (tokenData.refreshToken) {
    const enc = encryptValue(tokenData.refreshToken, orgId, masterSecret);
    encRefreshToken = enc.encryptedValue;
    refreshIv = enc.iv;
  }

  const connData = {
    orgId,
    provider,
    auth0Sub: tokenData.auth0Sub,
    displayName: tokenData.displayName,
    email: tokenData.email,
    encryptedAccessToken: encAccessToken,
    encryptedRefreshToken: encRefreshToken || null,
    accessTokenIv: accessIv,
    refreshTokenIv: refreshIv || null,
    maskedAccessToken: maskValue(tokenData.accessToken),
    grantedScopes: tokenData.grantedScopes,
    expiresAt: tokenData.expiresIn
      ? new Date(Date.now() + tokenData.expiresIn * 1000)
      : null,
    connectedBy,
    connectedAt: serverTimestamp(),
    lastUsedAt: null,
    usageCount: 0,
    active: true,
  };

  const ref = await addDoc(collection(db, "tokenVaultConnections"), connData);

  await logAudit({
    orgId,
    action: "connect",
    provider,
    connectionId: ref.id,
    actorId: connectedBy,
    actorType: "user",
    description: `Connected ${PROVIDER_CONFIG[provider].label} account (${tokenData.email})`,
    scopes: tokenData.grantedScopes,
  });

  return ref.id;
}

/** List all connections for an org */
export async function getConnections(orgId: string): Promise<TokenVaultConnection[]> {
  const q = query(
    collection(db, "tokenVaultConnections"),
    where("orgId", "==", orgId),
    where("active", "==", true),
  );
  const snap = await getDocs(q);
  return snap.docs.map((d) => toConnection(d.id, d.data()));
}

/** Get a single connection */
export async function getConnection(connectionId: string): Promise<TokenVaultConnection | null> {
  const snap = await getDoc(doc(db, "tokenVaultConnections", connectionId));
  if (!snap.exists()) return null;
  return toConnection(snap.id, snap.data());
}

/** Disconnect (soft-delete) a connection */
export async function disconnectConnection(
  connectionId: string,
  orgId: string,
  disconnectedBy: string,
): Promise<void> {
  const conn = await getConnection(connectionId);
  if (!conn || conn.orgId !== orgId) throw new Error("Connection not found");

  await updateDoc(doc(db, "tokenVaultConnections", connectionId), { active: false });

  // Revoke all approved requests for this connection
  const reqQ = query(
    collection(db, "tokenVaultRequests"),
    where("connectionId", "==", connectionId),
    where("status", "==", "approved"),
  );
  const reqSnap = await getDocs(reqQ);
  for (const d of reqSnap.docs) {
    await updateDoc(doc(db, "tokenVaultRequests", d.id), { status: "revoked" });
  }

  await logAudit({
    orgId,
    action: "disconnect",
    provider: conn.provider,
    connectionId,
    actorId: disconnectedBy,
    actorType: "user",
    description: `Disconnected ${PROVIDER_CONFIG[conn.provider].label} account (${conn.email})`,
  });
}

/** Decrypt and return an access token (for agent use) */
export async function getDecryptedToken(
  connectionId: string,
  orgId: string,
): Promise<{ accessToken: string; refreshToken?: string }> {
  const masterSecret = process.env.SECRETS_MASTER_KEY || process.env.NEXTAUTH_SECRET || "swarm-vault-default";
  const snap = await getDoc(doc(db, "tokenVaultConnections", connectionId));
  if (!snap.exists()) throw new Error("Connection not found");
  const data = snap.data();
  if (data.orgId !== orgId) throw new Error("Connection does not belong to org");

  const accessToken = decryptValue(data.encryptedAccessToken, data.accessTokenIv, orgId, masterSecret);
  let refreshToken: string | undefined;
  if (data.encryptedRefreshToken && data.refreshTokenIv) {
    refreshToken = decryptValue(data.encryptedRefreshToken, data.refreshTokenIv, orgId, masterSecret);
  }

  // Update usage stats
  await updateDoc(doc(db, "tokenVaultConnections", connectionId), {
    lastUsedAt: serverTimestamp(),
    usageCount: (data.usageCount || 0) + 1,
  });

  return { accessToken, refreshToken };
}

// ═══════════════════════════════════════════════════════════════
// Access Request CRUD
// ═══════════════════════════════════════════════════════════════

/** Calculate risk level from requested scopes */
export function calculateRiskLevel(provider: OAuthProvider, scopes: string[]): "low" | "medium" | "high" {
  const providerScopes = PROVIDER_CONFIG[provider].availableScopes;
  let maxRisk: "low" | "medium" | "high" = "low";
  for (const scope of scopes) {
    const scopeConfig = providerScopes.find((s) => s.id === scope);
    if (scopeConfig) {
      if (scopeConfig.risk === "high") return "high";
      if (scopeConfig.risk === "medium") maxRisk = "medium";
    }
  }
  return maxRisk;
}

/** Create an agent access request */
export async function createAccessRequest(
  orgId: string,
  agentId: string,
  agentName: string,
  connectionId: string,
  provider: OAuthProvider,
  requestedScopes: string[],
  reason: string,
): Promise<{ requestId: string; autoApproved: boolean }> {
  const riskLevel = calculateRiskLevel(provider, requestedScopes);
  const autoApproved = riskLevel === "low";

  const reqData = {
    orgId,
    agentId,
    agentName,
    connectionId,
    provider,
    requestedScopes,
    reason,
    riskLevel,
    status: autoApproved ? "approved" : "pending",
    reviewedBy: autoApproved ? "system" : null,
    reviewedAt: autoApproved ? serverTimestamp() : null,
    reviewNote: autoApproved ? "Auto-approved: all requested scopes are low-risk" : null,
    approvalExpiresAt: null,
    autoApproved,
    createdAt: serverTimestamp(),
  };

  const ref = await addDoc(collection(db, "tokenVaultRequests"), reqData);

  await logAudit({
    orgId,
    action: autoApproved ? "auto_approve" : "request",
    provider,
    connectionId,
    agentId,
    agentName,
    requestId: ref.id,
    scopes: requestedScopes,
    actorId: agentId,
    actorType: "agent",
    description: autoApproved
      ? `Auto-approved ${agentName} for ${PROVIDER_CONFIG[provider].label} (low-risk scopes: ${requestedScopes.join(", ")})`
      : `${agentName} requested ${PROVIDER_CONFIG[provider].label} access (${riskLevel} risk: ${requestedScopes.join(", ")})`,
  });

  return { requestId: ref.id, autoApproved };
}

/** Get all requests for an org */
export async function getAccessRequests(orgId: string, statusFilter?: string): Promise<TokenVaultRequest[]> {
  const constraints = [where("orgId", "==", orgId)];
  if (statusFilter) constraints.push(where("status", "==", statusFilter));

  const q = query(collection(db, "tokenVaultRequests"), ...constraints);
  const snap = await getDocs(q);
  return snap.docs.map((d) => toRequest(d.id, d.data()));
}

/** Approve an access request */
export async function approveRequest(
  requestId: string,
  orgId: string,
  reviewedBy: string,
  note?: string,
  expiresInDays?: number,
): Promise<void> {
  const snap = await getDoc(doc(db, "tokenVaultRequests", requestId));
  if (!snap.exists()) throw new Error("Request not found");
  const data = snap.data();
  if (data.orgId !== orgId) throw new Error("Request does not belong to org");
  if (data.status !== "pending") throw new Error("Request is not pending");

  await updateDoc(doc(db, "tokenVaultRequests", requestId), {
    status: "approved",
    reviewedBy,
    reviewedAt: serverTimestamp(),
    reviewNote: note || null,
    approvalExpiresAt: expiresInDays
      ? new Date(Date.now() + expiresInDays * 86400000)
      : null,
  });

  await logAudit({
    orgId,
    action: "approve",
    provider: data.provider,
    connectionId: data.connectionId,
    agentId: data.agentId,
    agentName: data.agentName,
    requestId,
    scopes: data.requestedScopes,
    actorId: reviewedBy,
    actorType: "user",
    description: `Approved ${data.agentName} for ${PROVIDER_CONFIG[data.provider as OAuthProvider].label} (${data.requestedScopes.join(", ")})`,
  });
}

/** Deny an access request */
export async function denyRequest(
  requestId: string,
  orgId: string,
  reviewedBy: string,
  note?: string,
): Promise<void> {
  const snap = await getDoc(doc(db, "tokenVaultRequests", requestId));
  if (!snap.exists()) throw new Error("Request not found");
  const data = snap.data();
  if (data.orgId !== orgId) throw new Error("Request does not belong to org");
  if (data.status !== "pending") throw new Error("Request is not pending");

  await updateDoc(doc(db, "tokenVaultRequests", requestId), {
    status: "denied",
    reviewedBy,
    reviewedAt: serverTimestamp(),
    reviewNote: note || null,
  });

  await logAudit({
    orgId,
    action: "deny",
    provider: data.provider,
    connectionId: data.connectionId,
    agentId: data.agentId,
    agentName: data.agentName,
    requestId,
    scopes: data.requestedScopes,
    actorId: reviewedBy,
    actorType: "user",
    description: `Denied ${data.agentName} for ${PROVIDER_CONFIG[data.provider as OAuthProvider].label}`,
    metadata: note ? { note } : undefined,
  });
}

/** Revoke an approved access request */
export async function revokeRequest(
  requestId: string,
  orgId: string,
  revokedBy: string,
): Promise<void> {
  const snap = await getDoc(doc(db, "tokenVaultRequests", requestId));
  if (!snap.exists()) throw new Error("Request not found");
  const data = snap.data();
  if (data.orgId !== orgId) throw new Error("Request does not belong to org");
  if (data.status !== "approved") throw new Error("Request is not approved");

  await updateDoc(doc(db, "tokenVaultRequests", requestId), { status: "revoked" });

  await logAudit({
    orgId,
    action: "revoke",
    provider: data.provider,
    connectionId: data.connectionId,
    agentId: data.agentId,
    agentName: data.agentName,
    requestId,
    scopes: data.requestedScopes,
    actorId: revokedBy,
    actorType: "user",
    description: `Revoked ${data.agentName} access to ${PROVIDER_CONFIG[data.provider as OAuthProvider].label}`,
  });
}

/** Check if an agent has approved access to a connection + scopes */
export async function checkAgentAccess(
  agentId: string,
  connectionId: string,
  requiredScopes: string[],
): Promise<{ allowed: boolean; requestId?: string; reason?: string }> {
  const q = query(
    collection(db, "tokenVaultRequests"),
    where("agentId", "==", agentId),
    where("connectionId", "==", connectionId),
    where("status", "==", "approved"),
  );
  const snap = await getDocs(q);

  for (const d of snap.docs) {
    const data = d.data();
    // Check expiry
    if (data.approvalExpiresAt) {
      const expiresAt = data.approvalExpiresAt instanceof Timestamp
        ? data.approvalExpiresAt.toDate()
        : new Date(data.approvalExpiresAt);
      if (expiresAt < new Date()) {
        await updateDoc(doc(db, "tokenVaultRequests", d.id), { status: "expired" });
        continue;
      }
    }
    // Check scopes
    const approvedScopes = new Set(data.requestedScopes || []);
    const missingScopes = requiredScopes.filter((s) => !approvedScopes.has(s));
    if (missingScopes.length === 0) {
      return { allowed: true, requestId: d.id };
    }
  }

  return { allowed: false, reason: "No approved access request covers the required scopes" };
}

// ═══════════════════════════════════════════════════════════════
// Audit Log
// ═══════════════════════════════════════════════════════════════

/** Log a token vault audit event */
export async function logAudit(entry: Omit<TokenVaultAuditEntry, "id" | "timestamp">): Promise<void> {
  await addDoc(collection(db, "tokenVaultAuditLog"), {
    ...entry,
    timestamp: serverTimestamp(),
  });
}

/** Get audit log for an org */
export async function getAuditLog(
  orgId: string,
  limitCount = 50,
  filters?: { agentId?: string; provider?: string; action?: string },
): Promise<TokenVaultAuditEntry[]> {
  const constraints = [where("orgId", "==", orgId)];
  if (filters?.agentId) constraints.push(where("agentId", "==", filters.agentId));
  if (filters?.provider) constraints.push(where("provider", "==", filters.provider));
  if (filters?.action) constraints.push(where("action", "==", filters.action));

  const q = query(
    collection(db, "tokenVaultAuditLog"),
    ...constraints,
    orderBy("timestamp", "desc"),
    firestoreLimit(limitCount),
  );
  const snap = await getDocs(q);
  return snap.docs.map((d) => toAuditEntry(d.id, d.data()));
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

/* eslint-disable @typescript-eslint/no-explicit-any */
function toConnection(id: string, data: any): TokenVaultConnection {
  return {
    id,
    orgId: data.orgId,
    provider: data.provider,
    auth0Sub: data.auth0Sub,
    displayName: data.displayName,
    email: data.email,
    encryptedAccessToken: data.encryptedAccessToken,
    encryptedRefreshToken: data.encryptedRefreshToken || undefined,
    accessTokenIv: data.accessTokenIv,
    refreshTokenIv: data.refreshTokenIv || undefined,
    maskedAccessToken: data.maskedAccessToken,
    grantedScopes: data.grantedScopes || [],
    expiresAt: data.expiresAt instanceof Timestamp ? data.expiresAt.toDate() : data.expiresAt ? new Date(data.expiresAt) : null,
    connectedBy: data.connectedBy,
    connectedAt: data.connectedAt instanceof Timestamp ? data.connectedAt.toDate() : null,
    lastUsedAt: data.lastUsedAt instanceof Timestamp ? data.lastUsedAt.toDate() : null,
    usageCount: data.usageCount || 0,
    active: data.active ?? true,
  };
}

function toRequest(id: string, data: any): TokenVaultRequest {
  return {
    id,
    orgId: data.orgId,
    agentId: data.agentId,
    agentName: data.agentName,
    connectionId: data.connectionId,
    provider: data.provider,
    requestedScopes: data.requestedScopes || [],
    reason: data.reason || "",
    riskLevel: data.riskLevel || "low",
    status: data.status,
    reviewedBy: data.reviewedBy || undefined,
    reviewedAt: data.reviewedAt instanceof Timestamp ? data.reviewedAt.toDate() : null,
    reviewNote: data.reviewNote || undefined,
    approvalExpiresAt: data.approvalExpiresAt instanceof Timestamp ? data.approvalExpiresAt.toDate() : null,
    autoApproved: data.autoApproved || false,
    createdAt: data.createdAt instanceof Timestamp ? data.createdAt.toDate() : null,
  };
}

function toAuditEntry(id: string, data: any): TokenVaultAuditEntry {
  return {
    id,
    orgId: data.orgId,
    action: data.action,
    provider: data.provider,
    connectionId: data.connectionId,
    agentId: data.agentId,
    agentName: data.agentName,
    requestId: data.requestId,
    scopes: data.scopes,
    actorId: data.actorId,
    actorType: data.actorType,
    description: data.description,
    metadata: data.metadata,
    timestamp: data.timestamp instanceof Timestamp ? data.timestamp.toDate() : null,
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */
