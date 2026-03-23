import type { OvidScope } from './types.js';

/**
 * Check if a list is a subset of another list.
 * Empty/undefined child list is always a subset.
 */
function isListSubset(child: string[] | undefined, parent: string[] | undefined): boolean {
  if (!child || child.length === 0) return true;
  if (!parent || parent.length === 0) return false;
  const parentSet = new Set(parent);
  return child.every(item => parentSet.has(item));
}

/**
 * Check if child deny list is a superset of parent deny list.
 * Child must deny at least everything parent denies.
 */
function isDenySupersetOrEqual(childDeny: string[] | undefined, parentDeny: string[] | undefined): boolean {
  if (!parentDeny || parentDeny.length === 0) return true;
  if (!childDeny || childDeny.length === 0) return false;
  const childSet = new Set(childDeny);
  return parentDeny.every(item => childSet.has(item));
}

function isCategorySubset(
  child: { allow?: string[]; deny?: string[] } | undefined,
  parent: { allow?: string[]; deny?: string[] } | undefined,
): boolean {
  if (!child) return true;
  if (!parent) {
    // Parent has no restrictions in this category — child can have any
    return true;
  }
  // Child allow must be subset of parent allow (if parent has allow list)
  if (parent.allow) {
    if (!isListSubset(child.allow, parent.allow)) return false;
  }
  // Child must deny at least everything parent denies
  if (!isDenySupersetOrEqual(child.deny, parent.deny)) return false;
  return true;
}

export function isSubsetScope(child: OvidScope, parent: OvidScope): boolean {
  for (const key of ['tools', 'shell', 'api', 'paths'] as const) {
    if (!isCategorySubset(child[key], parent[key])) return false;
  }
  return true;
}
