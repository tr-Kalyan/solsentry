import * as fs from 'fs';
import * as path from 'path';
import { Finding } from '../types';

// Signal 2: timestamp fields being written
const TIMESTAMP_RESET_PATTERN = /\.?\b(last_update_timestamp|last_accrual|last_update|last_rate_update|last_reward_timestamp|last_index_update|updated_at)\b\s*=/;

// Signal 3: integer division on financial fields
const FINANCIAL_DIVISION_PATTERN = /\.safe_div|\.safe_mul[\s\S]{0,50}\.safe_div|\b(reward|emission|rate|interest|yield|accrual|index|increment|delta|amount|fee)\w*\s*[\/][^=/]/i;

// Excluded: checked_div is safe (panics on overflow, doesn't silently truncate)
const SAFE_DIVISION_PATTERN = /checked_div|saturating_div/;

function findRustFiles(dir: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...findRustFiles(full));
    else if (entry.name.endsWith('.rs')) results.push(full);
  }
  return results;
}

function extractFunctionBody(content: string, fnName: string): string | null {
  // Find pub fn <name> or fn <name>
  const fnRegex = new RegExp(`(?:pub\\s+)?fn\\s+${fnName}\\s*[(<]`);
  const match = fnRegex.exec(content);
  if (!match) return null;

  // Walk forward to find matching braces
  let depth = 0;
  let started = false;
  let start = match.index;
  let i = start;

  while (i < content.length) {
    if (content[i] === '{') { depth++; started = true; }
    if (content[i] === '}') { depth--; }
    if (started && depth === 0) {
      return content.slice(start, i + 1);
    }
    i++;
  }
  return null;
}

function hasTimestampReset(body: string): boolean {
  const lines = body.split('\n');
  return lines.some(line => {
    return TIMESTAMP_RESET_PATTERN.test(line) && !line.trim().startsWith('//');
  });
}

function hasIntegerDivisionOnFinancialField(body: string): boolean {
  const lines = body.split('\n');
  return lines.some(line => {
    if (line.trim().startsWith('//')) return false;
    if (SAFE_DIVISION_PATTERN.test(line)) return false;
    return FINANCIAL_DIVISION_PATTERN.test(line);
  });
}

// Extract names of functions called inside a body
function extractCalleenames(body: string): string[] {
  const callees: string[] = [];
  const callRegex = /\b([a-z_][a-z0-9_]+)\s*\(/g;
  let m;
  while ((m = callRegex.exec(body)) !== null) {
    const name = m[1];
    // Skip common keywords and short names
    if (name.length > 4 && !['let', 'mut', 'pub', 'fn', 'if', 'for', 'while', 'match', 'return', 'Some', 'Ok', 'Err'].includes(name)) {
      callees.push(name);
    }
  }
  return [...new Set(callees)];
}

// Get body of function including one level of callees across all rust files
function getExpandedBody(fnName: string, rustFiles: string[]): string {
  let combined = '';
  let topBody = '';

  // First pass: find the top-level function body
  for (const file of rustFiles) {
    const fileContent = fs.readFileSync(file, 'utf-8');
    const body = extractFunctionBody(fileContent, fnName);
    if (body) {
      topBody = body;
      combined += body + '\n';
      break;
    }
  }

  if (!topBody) return combined;

  // Second pass: resolve callees across ALL files
  // Also try common dispatch patterns: update_rate -> update_rates, process_rate -> process_rates
  const callees = extractCalleenames(topBody);
  // Add plural variant of function name as callee candidate
  callees.push(fnName + 's');
  callees.push(fnName.replace(/_rate$/, '_rates'));
  callees.push(fnName.replace(/_reward$/, '_rewards'));
  for (const callee of callees) {
    for (const file of rustFiles) {
      const fileContent = fs.readFileSync(file, 'utf-8');
      const calleeBody = extractFunctionBody(fileContent, callee);
      if (calleeBody) {
        combined += calleeBody + '\n';
        break; // found it, move to next callee
      }
    }
  }

  return combined;
}

function getPermissionlessInstructions(idl: any): string[] {
  const result: string[] = [];
  for (const ix of idl.instructions || []) {
    const accounts = ix.accounts || [];
    const hasSigner = accounts.some((a: any) => a.isSigner === true);
    if (!hasSigner) result.push(ix.name);
  }
  return result;
}

function toCamelCase(snakeName: string): string {
  return snakeName.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}

export function checkPermissionlessAccumulationLoss(idl: any, programDir: string): Finding[] {
  const findings: Finding[] = [];
  if (!fs.existsSync(programDir)) return findings;

  const permissionlessInstructions = getPermissionlessInstructions(idl);
  if (permissionlessInstructions.length === 0) return findings;

  const rustFiles = findRustFiles(programDir);
  const seen = new Set<string>();

  // Whole-program scan: concat all source, check for both signals
  const allSource = rustFiles.map(f => fs.readFileSync(f, 'utf-8')).join('\n');
  const programHasTimestampReset = hasTimestampReset(allSource);
  const programHasIntDiv = hasIntegerDivisionOnFinancialField(allSource);

  // Only proceed if both signals exist somewhere in the program
  if (!programHasTimestampReset || !programHasIntDiv) return findings;

  for (const ixName of permissionlessInstructions) {
    const variants = [ixName, toCamelCase(ixName)];

    for (const fnName of variants) {
      const key = ixName;
      if (seen.has(key)) continue;
      seen.add(key);

      const relFile = `${fnName} (program-wide signals confirmed)`;
      {

        findings.push({
          rule: 'PERMISSIONLESS_ACCUMULATION_LOSS',
          severity: 'HIGH',
          instruction: ixName,
          account: 'N/A',
          intent: 'unknown',
          confidence: 'high',
          status: 'needs_manual_verification',
          attackPath: `'${ixName}' is permissionless (no signer required) and resets a timestamp after integer division on a financial field. An attacker can call this repeatedly at high cadence, forcing each interval to truncate to zero. Fractional rewards lost per call accumulate into material under-accrual over time. Cost to attacker: only transaction fees.`,
          expectedBehavior: `'${ixName}' should either: (1) require a trusted signer/keeper, (2) enforce a minimum update interval, or (3) use carry-forward fractional accounting so truncated remainders are not discarded.`,
          observedBehavior: `Permissionless instruction resets timestamp AND performs integer division on financial field in ${relFile}. Repeated micro-calls suppress reward accrual via accumulated rounding loss.`,
          mismatch: true,
          verificationSteps: [
            {
              check: 'Confirm no signer in IDL accounts',
              grepPattern: `isSigner.*true`,
              scopedTo: `IDL: ${ixName}`,
              expected: 'must_not_exist',
            },
            {
              check: 'Confirm timestamp reset in function body',
              grepPattern: `last_update_timestamp\\s*=|last_accrual\\s*=`,
              scopedTo: relFile,
              expected: 'must_exist',
            },
            {
              check: 'Confirm integer division on reward/rate field',
              grepPattern: `reward.*\/|rate.*\/|emission.*\/|index.*\/`,
              scopedTo: relFile,
              expected: 'must_exist',
            },
            {
              check: 'Check if minimum update interval exists',
              grepPattern: `min_interval|cooldown|require.*timestamp`,
              scopedTo: relFile,
              expected: 'context_dependent',
            },
          ],
          claudePrompt: `'${ixName}' in ${relFile} is permissionless and contains both a timestamp reset and integer division on a financial field. This matches the Permissionless Accumulation Loss pattern. Verify: (1) Can anyone call this without signing? (2) Does the function reset last_update_timestamp after computing reward/rate? (3) Is the division floored (integer, not fixed-point)? (4) Is there a minimum interval guard preventing rapid re-calls? If all four conditions hold, an attacker can call this at high cadence to force repeated truncation — each call loses fractional rewards that are never recovered. Compare single coarse update vs 1000 micro-updates over the same period to quantify loss. Note: impact depends on emission rate and token decimals — low emission rates with 9 decimals may truncate to 0 per call. Calculate max loss as: emission_per_second / SECONDS_PER_YEAR * decimals_factor to assess materiality before submitting.`,
          flowDetected: true,
          flowType: 'NONE',
        });
      }
    }
  }

  return findings;
}
