import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

import type { ApprovalRiskCode } from "../types";
import { isPathInside } from "./paths";

const errorWithCodeSchema = z.object({ code: z.string() }).passthrough();

export const AUTO_APPROVE_PATTERNS: RegExp[] = [
  /^ls\b/,
  /^pwd$/,
  /^echo\b/,
  /^which\b/,
  /^type\b/,
  /^git\s+(status|log|diff|branch)\b/,
  /^node\s+--version$/,
  /^bun\s+--version$/,
];

export const ALWAYS_WARN_PATTERNS: RegExp[] = [
  /\brm\s+-rf\b/,
  /\bgit\s+push\s+--force\b/,
  /\bgit\s+reset\s+--hard\b/,
  /\bchmod\b/,
  /\bchown\b/,
  /\bsudo\b/,
  /\bcurl\b.*\|\s*bash/,
  /\bdrop\s+table\b/i,
  /\bdelete\s+from\b/i,
];

export type CommandApprovalClassification =
  | { kind: "auto" }
  | { kind: "prompt"; dangerous: boolean };

export type CommandApprovalClassificationDetailed =
  | { kind: "auto"; dangerous: false; riskCode: "safe_auto_approved" }
  | {
      kind: "prompt";
      dangerous: boolean;
      riskCode: Exclude<ApprovalRiskCode, "safe_auto_approved">;
    };

export type CommandApprovalContext = {
  allowedRoots?: string[];
  workingDirectory?: string;
};

const FILE_READ_REVIEW_PATTERNS: RegExp[] = [/^cat\b/, /^head\b/, /^tail\b/, /^man\b/];

// Quote-aware detection of syntax the shell expands before execution. The
// scope check resolves tokens as workspace-relative paths, but bash expands
// `~`, `$var`, and brace expressions at runtime, so an unexpanded token cannot
// vouch for where the command actually reads or writes. A single regex cannot
// model where expansions are legal, so detection is a small scanner with
// deliberately conservative semantics:
// - single quotes expand nothing (backslashes included) — they remain the
//   documented way to pass a literal `$VAR` through an auto-approved command
// - double quotes expand `$`, and `~`-looking words are flagged conservatively
//   because downstream programs sometimes expand those themselves
// - `~` expands at the start of a word (after whitespace, `=`, or `:`), while
//   mid-word `~` like `git diff HEAD~1` stays literal
// - `\X` backslash escapes suppress expansion of the next character
// - `{a,b}` and `{1..2}` brace expansion outside quotes is flagged
// - any `$` followed by a non-whitespace, non-quote character is treated as
//   expandable: named variables, positional parameters (`$5`), and special
//   parameters (`$@`, `$$`) alike — the classifier cannot see their values.
function containsShellExpansionSyntax(command: string): boolean {
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command.charAt(i);

    // Inside single quotes bash expands nothing, backslashes included.
    if (quote === "'") {
      if (ch === "'") quote = null;
      continue;
    }

    // Backslash escapes the next character, suppressing expansion of it.
    if (ch === "\\") {
      i++;
      continue;
    }

    if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === "$") return true;
      else if (ch === "~") {
        // bash keeps a quoted `~` literal, but downstream tools sometimes
        // expand a leading `~` themselves, so flag it conservatively.
        const prev = i > 0 ? command.charAt(i - 1) : undefined;
        if (prev === '"' || prev === undefined || /[\s=:]/.test(prev)) return true;
      }
      continue;
    }

    if (ch === "'") {
      quote = "'";
      continue;
    }
    if (ch === '"') {
      quote = '"';
      continue;
    }

    // `$` followed by anything but whitespace, a quote, or end-of-string can
    // expand — variables, positional parameters, and special parameters.
    if (ch === "$") {
      const next = i + 1 < command.length ? command.charAt(i + 1) : undefined;
      if (next !== undefined && !/[\s'"`]/.test(next)) return true;
      continue;
    }

    // Tilde expands at the start of a word only; mid-word tildes (HEAD~1)
    // stay literal.
    if (ch === "~") {
      const prev = i > 0 ? command.charAt(i - 1) : undefined;
      if (prev === undefined || /[\s=:]/.test(prev)) return true;
      continue;
    }

    // Brace expansion: {a,b} or {1..2} outside quotes. Single-element braces
    // like {a} do not expand in bash.
    if (ch === "{") {
      const close = command.indexOf("}", i);
      if (close > i) {
        const body = command.slice(i + 1, close);
        if (body.includes(",") || body.includes("..")) return true;
      }
    }
  }
  return false;
}

function hasShellControlOperators(command: string): boolean {
  // Conservative: if the command contains obvious shell control operators or
  // redirections, don't auto-approve even if it starts with a "safe" command.
  // This avoids cases like: `ls; rm -rf /`.
  return (
    command.includes("\n") ||
    command.includes("\r") ||
    command.includes(";") ||
    command.includes("&&") ||
    command.includes("||") ||
    command.includes("|") ||
    command.includes(">") ||
    command.includes("<") ||
    command.includes("`") ||
    command.includes("$(") ||
    command.includes("&")
  );
}

export function classifyCommand(command: string): CommandApprovalClassification {
  const detailed = classifyCommandDetailed(command);
  if (detailed.kind === "auto") return { kind: "auto" };
  return { kind: "prompt", dangerous: detailed.dangerous };
}

function tokenizeCommand(command: string): string[] {
  const tokens: string[] = [];
  const re =
    /((?:--[a-zA-Z0-9-]+|-[a-zA-Z0-9])=(?:"[^"]*"|'[^']*'|`[^`]*`|\S+)|"([^"]*)"|'([^']*)'|`([^`]*)`|(\S+))/g;
  let m: RegExpExecArray | null = null;
  while ((m = re.exec(command)) !== null) {
    // Prefer de-quoted captures first so absolute path checks work for
    // commands like: ls "/tmp/path"
    const token = m[2] ?? m[3] ?? m[4] ?? m[5] ?? m[1] ?? "";
    if (token) tokens.push(token);
  }
  return tokens;
}

function canonicalizeExistingPrefixSync(targetPath: string): string {
  const resolved = path.resolve(targetPath);
  const tail: string[] = [];
  let cursor = resolved;

  while (true) {
    try {
      const canonical = fs.realpathSync.native(cursor);
      return tail.length > 0 ? path.join(canonical, ...tail.reverse()) : canonical;
    } catch (err) {
      const parsedCode = errorWithCodeSchema.safeParse(err);
      const code = parsedCode.success ? parsedCode.data.code : undefined;
      if (code !== "ENOENT") throw err;
      const parent = path.dirname(cursor);
      if (parent === cursor) return resolved;
      tail.push(path.basename(cursor));
      cursor = parent;
    }
  }
}

function canonicalizeRootSync(rootPath: string): string {
  const resolved = path.resolve(rootPath);
  try {
    return fs.realpathSync.native(resolved);
  } catch (err) {
    const parsedCode = errorWithCodeSchema.safeParse(err);
    const code = parsedCode.success ? parsedCode.data.code : undefined;
    if (code !== "ENOENT") throw err;
    return resolved;
  }
}

/** Extract path-like values from option-assigned forms: --option=/path or -o=/path */
function stripWrappingQuotes(value: string): string {
  let current = value;
  while (
    current.length >= 2 &&
    ((current.startsWith('"') && current.endsWith('"')) ||
      (current.startsWith("'") && current.endsWith("'")) ||
      (current.startsWith("`") && current.endsWith("`")))
  ) {
    current = current.slice(1, -1);
  }
  return current;
}

function isRelativePathLike(value: string): boolean {
  if (!value || value.startsWith("-")) return false;
  if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value)) return false;

  return (
    value === "." ||
    value === ".." ||
    value.startsWith("./") ||
    value.startsWith(".\\") ||
    value.startsWith("../") ||
    value.startsWith("..\\") ||
    value.includes("/") ||
    value.includes("\\")
  );
}

function extractPathsFromToken(token: string, workingDirectory?: string): string[] {
  const paths: string[] = [];
  const optionValueMatch = token.match(/^(?:--[a-zA-Z0-9-]+|-[a-zA-Z0-9])=(.+)$/);
  if (optionValueMatch) {
    const value = stripWrappingQuotes(optionValueMatch[1] ?? "");
    if (!value) return paths;

    if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value)) {
      paths.push(value);
      return paths;
    }

    if (workingDirectory && isRelativePathLike(value)) {
      paths.push(path.resolve(workingDirectory, value));
    }
  }
  return paths;
}

function hasOutsideAllowedScope(command: string, allowedRoots?: string[], workingDirectory?: string): boolean {
  if (!allowedRoots || allowedRoots.length === 0) return false;
  const normalizedRoots = allowedRoots.map((root) => {
    try {
      return canonicalizeRootSync(root);
    } catch {
      return path.resolve(root);
    }
  });
  const normalizedWorkingDirectory = (() => {
    if (!workingDirectory) return undefined;
    try {
      return canonicalizeRootSync(workingDirectory);
    } catch {
      return path.resolve(workingDirectory);
    }
  })();

  for (const token of tokenizeCommand(command)) {
    const pathsToCheck: string[] = [];
    if (path.posix.isAbsolute(token) || path.win32.isAbsolute(token)) {
      pathsToCheck.push(token);
    }
    if (normalizedWorkingDirectory && isRelativePathLike(token)) {
      pathsToCheck.push(path.resolve(normalizedWorkingDirectory, token));
    }
    pathsToCheck.push(...extractPathsFromToken(token, normalizedWorkingDirectory));
    for (const p of pathsToCheck) {
      let resolved: string;
      try {
        resolved = canonicalizeExistingPrefixSync(p);
      } catch {
        return true;
      }
      const inside = normalizedRoots.some((root) => isPathInside(root, resolved));
      if (!inside) return true;
    }
  }
  return false;
}

export function classifyCommandDetailed(
  command: string,
  ctx: CommandApprovalContext = {}
): CommandApprovalClassificationDetailed {
  const dangerous = ALWAYS_WARN_PATTERNS.some((p) => p.test(command));
  if (dangerous) {
    return { kind: "prompt", dangerous: true, riskCode: "matches_dangerous_pattern" };
  }

  if (hasShellControlOperators(command)) {
    return { kind: "prompt", dangerous: false, riskCode: "contains_shell_control_operator" };
  }

  if (hasOutsideAllowedScope(command, ctx.allowedRoots, ctx.workingDirectory)) {
    return { kind: "prompt", dangerous: false, riskCode: "outside_allowed_scope" };
  }

  // Fail closed on syntax the shell could expand (~, $var, {a,b}): the scope
  // check above only sees unexpanded tokens, so it cannot vouch for where
  // these actually land once the shell is done with them. This runs even
  // without configured allowed roots, mirroring how file-read review patterns
  // stay unconditional: reading $HOME/.ssh is worth a prompt either way.
  if (containsShellExpansionSyntax(command)) {
    return { kind: "prompt", dangerous: false, riskCode: "requires_manual_review" };
  }

  if (FILE_READ_REVIEW_PATTERNS.some((p) => p.test(command))) {
    return { kind: "prompt", dangerous: false, riskCode: "file_read_command_requires_review" };
  }

  if (AUTO_APPROVE_PATTERNS.some((p) => p.test(command))) {
    return { kind: "auto", dangerous: false, riskCode: "safe_auto_approved" };
  }

  return { kind: "prompt", dangerous: false, riskCode: "requires_manual_review" };
}

export async function approveCommand(
  command: string,
  prompt: (message: string) => Promise<string>
): Promise<boolean> {
  const classification = classifyCommandDetailed(command);
  if (classification.kind === "auto") return true;

  const prefix = classification.dangerous ? "DANGEROUS: " : "Run: ";
  const answer = await prompt(
    `${prefix}${command}\nRisk: ${classification.riskCode}\nApprove? [y/N] `
  );
  return answer.trim().toLowerCase() === "y";
}
