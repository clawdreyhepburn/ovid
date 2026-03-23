/**
 * Basic structural validation for Cedar policy text.
 * Not a full parser — catches obvious syntax issues.
 */
export function validateCedarSyntax(policySet: string): { valid: boolean; error?: string } {
  const trimmed = policySet.trim();

  if (!trimmed) {
    return { valid: false, error: 'Policy set is empty' };
  }

  // Must contain at least one permit or forbid statement
  const hasPermit = /\bpermit\b/.test(trimmed);
  const hasForbid = /\bforbid\b/.test(trimmed);
  if (!hasPermit && !hasForbid) {
    return { valid: false, error: 'Policy must contain at least one "permit" or "forbid" statement' };
  }

  // Check for unmatched quotes
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let parenDepth = 0;

  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i];
    const prev = i > 0 ? trimmed[i - 1] : '';

    if (ch === '"' && !inSingleQuote && prev !== '\\') {
      inDoubleQuote = !inDoubleQuote;
    } else if (ch === "'" && !inDoubleQuote && prev !== '\\') {
      inSingleQuote = !inSingleQuote;
    } else if (!inSingleQuote && !inDoubleQuote) {
      if (ch === '(') parenDepth++;
      else if (ch === ')') {
        parenDepth--;
        if (parenDepth < 0) {
          return { valid: false, error: 'Unmatched closing parenthesis' };
        }
      }
    }
  }

  if (inSingleQuote || inDoubleQuote) {
    return { valid: false, error: 'Unmatched quote in policy text' };
  }

  if (parenDepth !== 0) {
    return { valid: false, error: 'Unmatched opening parenthesis' };
  }

  // Each permit/forbid block must end with a semicolon.
  // Strategy: find all permit/forbid keywords (outside quotes) and ensure
  // there's a semicolon after each block's closing paren.
  const statementPattern = /\b(permit|forbid)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = statementPattern.exec(trimmed)) !== null) {
    // Find the matching close paren
    let depth = 0;
    let foundOpen = false;
    let endIdx = match.index;
    for (let i = match.index; i < trimmed.length; i++) {
      const c = trimmed[i];
      if (c === '(') { depth++; foundOpen = true; }
      else if (c === ')') {
        depth--;
        if (depth === 0 && foundOpen) {
          endIdx = i;
          break;
        }
      }
    }

    // After the closing paren, skip optional whitespace/braces/conditions, must eventually hit semicolon
    let foundSemicolon = false;
    let braceDepth = 0;
    for (let i = endIdx + 1; i < trimmed.length; i++) {
      const c = trimmed[i];
      if (c === '{') braceDepth++;
      else if (c === '}') braceDepth--;
      else if (c === ';' && braceDepth === 0) {
        foundSemicolon = true;
        break;
      }
      // If we hit the next permit/forbid at brace depth 0, semicolon is missing
      if (braceDepth === 0 && /\b(permit|forbid)\b/.test(trimmed.slice(i, i + 7))) {
        break;
      }
    }

    if (!foundSemicolon) {
      return { valid: false, error: 'Statement missing terminating semicolon' };
    }
  }

  return { valid: true };
}
