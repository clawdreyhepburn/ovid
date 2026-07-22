/**
 * Shared authorization vocabulary for the OVID stack.
 *
 * One conceptual model, two projections:
 *   - Ovid::*  — per-agent mandates (identity + attenuated permission)
 *   - Jans::*  — Carapace deployment ceiling (tools / shell / APIs)
 *
 * Mandates are written against the Ovid verbs below. Subset proofs and
 * Carapace integration project into Jans where a mapping exists.
 *
 * This is NOT RBAC. There are no roles/profiles — only actions + resource
 * constraints that compile to Cedar.
 */

/** Agent-facing mandate verbs (Ovid::Action). */
export const MANDATE_ACTIONS = [
  'read',
  'write',
  'edit',
  'exec',
  'fetch',
  'search',
  'browse',
  'send',
  'delegate',
  'remember',
  'recall',
  'call_tool',
  'summarize',
] as const;

export type MandateAction = (typeof MANDATE_ACTIONS)[number];

/** Resource kinds addressable in a mandate. */
export const RESOURCE_KINDS = [
  'File',
  'Shell',
  'Tool',
  'WebEndpoint',
  'Channel',
  'Memory',
  'Session',
  'API', // Jans-facing alias; builder normalizes WebEndpoint ↔ API
] as const;

export type ResourceKind = (typeof RESOURCE_KINDS)[number];

/** Default safe mandate when no intent is supplied. */
export const DEFAULT_MANDATE_ACTIONS: readonly MandateAction[] = [
  'read',
  'search',
  'summarize',
] as const;

/**
 * Projection from Ovid mandate action → Carapace (Jans) action + resource kind.
 * `null` means "no direct deployment-ceiling equivalent" (OVID-only verb).
 */
export interface JansProjection {
  action: 'exec_command' | 'call_api' | 'call_tool' | 'list_tools';
  resourceKind: 'Shell' | 'API' | 'Tool';
}

export const OVID_TO_JANS: Partial<Record<MandateAction, JansProjection>> = {
  exec: { action: 'exec_command', resourceKind: 'Shell' },
  fetch: { action: 'call_api', resourceKind: 'API' },
  search: { action: 'call_api', resourceKind: 'API' },
  browse: { action: 'call_api', resourceKind: 'API' },
  call_tool: { action: 'call_tool', resourceKind: 'Tool' },
  // File verbs often arrive as OpenClaw tools (read/write/edit) — map as tools
  // when the resource is Tool-shaped; pure File path constraints stay Ovid-only
  // for Carapace (Carapace gates the write/edit tools via Tool resource + path context).
  read: { action: 'call_tool', resourceKind: 'Tool' },
  write: { action: 'call_tool', resourceKind: 'Tool' },
  edit: { action: 'call_tool', resourceKind: 'Tool' },
};

/** OpenClaw built-in tool name → default Ovid action (plugin mapper source). */
export const OPENCLAW_TOOL_TO_ACTION: Record<string, MandateAction> = {
  read: 'read',
  write: 'write',
  edit: 'edit',
  exec: 'exec',
  process: 'exec',
  web_fetch: 'fetch',
  web_search: 'search',
  browser: 'browse',
  message: 'send',
  sessions_spawn: 'delegate',
  memory_search: 'recall',
  memory_get: 'recall',
  tts: 'call_tool',
  image: 'read',
  pdf: 'read',
  image_generate: 'call_tool',
  video_generate: 'call_tool',
};

export function isMandateAction(x: unknown): x is MandateAction {
  return typeof x === 'string' && (MANDATE_ACTIONS as readonly string[]).includes(x);
}

export function isResourceKind(x: unknown): x is ResourceKind {
  return typeof x === 'string' && (RESOURCE_KINDS as readonly string[]).includes(x);
}

/** Normalize API → WebEndpoint for Ovid entity typing. */
export function ovidResourceKind(kind: ResourceKind): Exclude<ResourceKind, 'API'> {
  return kind === 'API' ? 'WebEndpoint' : kind;
}

/** Normalize WebEndpoint → API for Jans entity typing. */
export function jansResourceKind(kind: ResourceKind): 'Shell' | 'API' | 'Tool' | 'File' | 'Channel' | 'Memory' | 'Session' {
  if (kind === 'WebEndpoint') return 'API';
  if (kind === 'API' || kind === 'Shell' || kind === 'Tool') return kind;
  return kind as 'File' | 'Channel' | 'Memory' | 'Session';
}
