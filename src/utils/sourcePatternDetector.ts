import * as fs from 'fs';
import * as path from 'path';

export interface SourceProtection {
  hasTokenAuthority: boolean;
  hasInterfaceType: boolean;
  hasProgramType: boolean;
  hasAddressConstraint: boolean;
  hasAdminGate: boolean;
}

export function detectSourceProtection(
  accountName: string,
  programDir: string
): SourceProtection {
  const result: SourceProtection = {
    hasTokenAuthority: false,
    hasInterfaceType: false,
    hasProgramType: false,
    hasAddressConstraint: false,
    hasAdminGate: false,
  };

  if (!fs.existsSync(programDir)) return result;

  const rustFiles = findRustFiles(programDir);

  for (const file of rustFiles) {
    const content = fs.readFileSync(file, 'utf-8');

    // Find the account declaration block
    const accountIndex = content.indexOf(`${accountName}`);
    if (accountIndex === -1) continue;

    // Extract surrounding context (~200 chars before and after)
    const start = Math.max(0, accountIndex - 200);
    const end = Math.min(content.length, accountIndex + 200);
    const context = content.slice(start, end);

    if (/token::authority/.test(context)) result.hasTokenAuthority = true;
    if (/Interface<'info,\s*TokenInterface>/.test(context)) result.hasInterfaceType = true;
    if (/Program<'info,\s*Token/.test(context)) result.hasProgramType = true;
    if (/address\s*=\s*(\w+::)+id\(\)|address\s*=\s*crate::/.test(context))
  result.hasAddressConstraint = true;
    if (/constraint\s*=.*owner.*==.*admin|admin::ID/.test(context)) result.hasAdminGate = true;
    if (/has_one\s*=\s*\w+/.test(context)) result.hasAdminGate = true;
  }

  return result;
}

function findRustFiles(dir: string): string[] {
  const results: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...findRustFiles(fullPath));
    else if (entry.name.endsWith('.rs')) results.push(fullPath);
  }
  return results;
}