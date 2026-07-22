/**
 * Mandate builder — compile a structured intent object into a Cedar policySet.
 *
 * Motivation: authoring raw Cedar in a spawn task is error-prone. A model (or a
 * human) is far more accurate filling a constrained form than writing free
 * Cedar. The builder is the "form → policy" compiler. Output is a policySet
 * string that the OVID-ME fallback engine and cedar-wasm both accept, so the
 * same mandate is enforceable and provable.
 *
 * Design rules:
 *   - Mandates, not roles. No profile indirection.
 *   - Only emit Cedar syntax the OVID-ME fallback parser supports:
 *       permit(principal, action in [Ovid::Action::"x", ...], resource)
 *         [when { resource.path like "glob" }]
 *       permit(principal, action == Ovid::Action::"x", resource == Ovid::Shell::"git")
 *       forbid(...) same shapes
 *     (no unless, no && / ||, no context.* beyond resource.path like)
 *   - Deny-by-default: an empty allow list yields a policySet that grants
 *     nothing (Cedar default-deny). We still emit a benign no-op permit so the
 *     validator sees a statement.
 */

import {
  DEFAULT_MANDATE_ACTIONS,
  MANDATE_ACTIONS as MANDATE_ACTIONS_ALL,
  isMandateAction,
  isResourceKind,
  ovidResourceKind,
  type MandateAction,
  type ResourceKind,
} from './vocabulary.js';

export interface ResourceConstraint {
  /** Cedar entity kind. Omit for a bare action grant (resource wildcard). */
  type?: ResourceKind;
  /**
   * Exact resource id (compiles to `resource == Ovid::<Type>::"id"`).
   * For Shell this is a binary name (git, npm); for Tool a tool name; for
   * WebEndpoint a hostname; for Channel a provider; etc.
   */
  in?: string[];
  /**
   * Path glob (compiles to `when { resource.path like "glob" }`).
   * Only meaningful for File / Memory resources. Single glob per grant;
   * multiple globs → multiple grants.
   */
  pathLike?: string[];
}

export interface GrantIntent {
  /** One or more mandate verbs this grant permits. */
  action: MandateAction | MandateAction[];
  /** Optional resource scoping. Omit for "any resource of any kind". */
  resource?: ResourceConstraint;
  /** permit (default) or forbid. */
  effect?: 'permit' | 'forbid';
}

export interface MandateIntent {
  /** Grants. Empty/omitted → the safe default (read/search/summarize). */
  allow?: GrantIntent[];
  /** Explicit forbids (always win, per Cedar). */
  forbid?: GrantIntent[];
  /** TTL hint carried alongside the mandate (seconds). */
  ttlSeconds?: number;
  /** Cedar namespace for actions/resources. Default: "Ovid". */
  namespace?: string;
}

export interface BuildResult {
  policySet: string;
  ttlSeconds?: number;
  /** Human-readable summary of what was granted. */
  summary: string;
  /** Non-fatal notes (e.g. dropped unknown actions). */
  warnings: string[];
}

const IDENT = /^[A-Za-z0-9_.+@:-]+$/; // conservative id charset for Cedar string literals

function quoteId(id: string): string {
  // Cedar string literal; reject anything that could break the literal.
  if (!IDENT.test(id)) {
    throw new Error(`unsafe resource id for Cedar literal: ${JSON.stringify(id)}`);
  }
  return `"${id}"`;
}

function sanitizeGlob(glob: string): string {
  // A when { resource.path like "..." } literal. Disallow embedded quotes/newlines.
  if (/["\n\r\\]/.test(glob)) {
    throw new Error(`unsafe path glob for Cedar literal: ${JSON.stringify(glob)}`);
  }
  return glob;
}

function normActions(a: MandateAction | MandateAction[]): { actions: MandateAction[]; dropped: string[] } {
  const arr = Array.isArray(a) ? a : [a];
  const actions: MandateAction[] = [];
  const dropped: string[] = [];
  for (const x of arr) {
    if (isMandateAction(x)) actions.push(x);
    else dropped.push(String(x));
  }
  return { actions, dropped };
}

function actionClause(ns: string, actions: MandateAction[]): string {
  if (actions.length === 1) {
    return `action == ${ns}::Action::"${actions[0]}"`;
  }
  const list = actions.map((a) => `${ns}::Action::"${a}"`).join(', ');
  return `action in [${list}]`;
}

/**
 * Emit the Cedar statements for one grant. May emit multiple statements when a
 * grant has multiple resource ids or path globs (each is its own statement so
 * the fallback parser — one resource-equality / one glob per block — stays happy).
 */
function emitGrant(ns: string, grant: GrantIntent, warnings: string[]): string[] {
  const effect = grant.effect ?? 'permit';
  const { actions, dropped } = normActions(grant.action);
  for (const d of dropped) warnings.push(`dropped unknown action "${d}"`);
  if (actions.length === 0) return [];

  const clause = actionClause(ns, actions);
  const rc = grant.resource;

  // No resource scoping → wildcard resource.
  if (!rc || (!rc.in?.length && !rc.pathLike?.length && !rc.type)) {
    return [`${effect}(principal, ${clause}, resource);`];
  }

  const stmts: string[] = [];

  // Resource-equality grants (Shell/Tool/WebEndpoint/Channel/... ids).
  if (rc.in?.length) {
    const kind = rc.type ? ovidResourceKind(rc.type) : 'Tool';
    for (const id of rc.in) {
      stmts.push(`${effect}(principal, ${clause}, resource == ${ns}::${kind}::${quoteId(id)});`);
    }
  }

  // Path-glob grants (File/Memory).
  if (rc.pathLike?.length) {
    for (const glob of rc.pathLike) {
      stmts.push(
        `${effect}(principal, ${clause}, resource) when { resource.path like "${sanitizeGlob(glob)}" };`,
      );
    }
  }

  // Type-only grant (kind given, no ids/globs) → wildcard within kind. Cedar
  // can't express "any resource of type T" in the supported subset without a
  // resource.type check (unsupported), so we fall back to a wildcard-resource
  // grant and note it.
  if (rc.type && !rc.in?.length && !rc.pathLike?.length) {
    warnings.push(
      `resource.type "${rc.type}" with no ids/paths → wildcard resource (kind not enforced in fallback engine)`,
    );
    stmts.push(`${effect}(principal, ${clause}, resource);`);
  }

  return stmts;
}

/**
 * Compile a structured intent into a Cedar policySet string + metadata.
 */
export function buildMandate(intent: MandateIntent = {}): BuildResult {
  const warnings: string[] = [];
  const ns = intent.namespace ?? 'Ovid';
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(ns)) {
    throw new Error(`invalid Cedar namespace: ${JSON.stringify(ns)}`);
  }

  const allow = intent.allow ?? [];
  const forbid = intent.forbid ?? [];

  const stmts: string[] = [];

  if (allow.length === 0 && forbid.length === 0) {
    // Safe default.
    stmts.push(
      `permit(principal, ${actionClause(ns, [...DEFAULT_MANDATE_ACTIONS])}, resource);`,
    );
    warnings.push('no intent supplied — emitted default read/search/summarize mandate');
  } else {
    for (const g of allow) stmts.push(...emitGrant(ns, { ...g, effect: 'permit' }, warnings));
    for (const g of forbid) stmts.push(...emitGrant(ns, { ...g, effect: 'forbid' }, warnings));
    if (stmts.length === 0) {
      // Everything was dropped/empty → deny-all. A forbid over the full verb
      // set grants nothing and parses cleanly (Cedar is default-deny anyway,
      // but an explicit forbid documents intent and satisfies validators).
      stmts.push(`forbid(principal, ${actionClause(ns, [...MANDATE_ACTIONS_ALL])}, resource);`);
      warnings.push('all grants were empty or invalid — mandate grants nothing');
    }
  }

  const policySet = stmts.join('\n');
  return {
    policySet,
    ttlSeconds: intent.ttlSeconds,
    summary: summarize(allow, forbid),
    warnings,
  };
}

function summarize(allow: GrantIntent[], forbid: GrantIntent[]): string {
  if (allow.length === 0 && forbid.length === 0) return 'default: read, search, summarize';
  const parts: string[] = [];
  for (const g of allow) parts.push(describeGrant('allow', g));
  for (const g of forbid) parts.push(describeGrant('deny', g));
  return parts.join('; ');
}

function describeGrant(prefix: string, g: GrantIntent): string {
  const acts = (Array.isArray(g.action) ? g.action : [g.action]).join('/');
  const rc = g.resource;
  if (!rc) return `${prefix} ${acts} (any)`;
  if (rc.in?.length) return `${prefix} ${acts} ${rc.type ?? 'Tool'} [${rc.in.join(',')}]`;
  if (rc.pathLike?.length) return `${prefix} ${acts} path [${rc.pathLike.join(',')}]`;
  if (rc.type) return `${prefix} ${acts} ${rc.type}:*`;
  return `${prefix} ${acts}`;
}

/**
 * Emit the spawn-task tag block that the openclaw-ovid hook parses:
 *   [OVID_TTL:n]
 *   [OVID_MANDATE] ... [/OVID_MANDATE]
 * Ready to prepend to a sessions_spawn task string.
 */
export function buildMandateTag(intent: MandateIntent = {}): { tag: string; result: BuildResult } {
  const result = buildMandate(intent);
  const ttlLine = result.ttlSeconds ? `[OVID_TTL:${result.ttlSeconds}]\n` : '';
  const tag = `${ttlLine}[OVID_MANDATE]\n${result.policySet}\n[/OVID_MANDATE]`;
  return { tag, result };
}

/** Re-export the vocab surface so consumers get one import. */
export {
  MANDATE_ACTIONS,
  RESOURCE_KINDS,
  DEFAULT_MANDATE_ACTIONS,
  isMandateAction,
  isResourceKind,
} from './vocabulary.js';
export type { MandateAction, ResourceKind } from './vocabulary.js';
