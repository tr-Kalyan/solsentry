import * as fs from 'fs';
import * as path from 'path';
import { Finding } from '../types';

const CRITICAL_FIELDS = ['tick', 'price', 'amount', 'balance', 'liquidity', 'sqrt_price', 'fee_rate'];
const OVERWRITE_REGEX = /(\w+)\.(tick|price|amount|balance|liquidity|sqrt_price|fee_rate)\w*\s*=\s*(\w+)\.(\w+)/g;
const VALIDATION_SIGNALS = [
  'require!', 'assert!', 'assert_eq!',
  'validate', 'check', 'verify', 'ensure'
];

const HIGH_RISK_SOURCES = ['position', 'oracle', 'price_feed', 'external'];

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

function hasValidationNearby(lines: string[], lineIndex: number, sourceVar: string, fieldName: string): boolean {
  const start = Math.max(0, lineIndex - 15);
  const window = lines.slice(start, lineIndex + 5).join('\n');
  return VALIDATION_SIGNALS.some(s =>
    window.includes(s) &&
    (window.includes(sourceVar) || window.includes(fieldName))
  );
}

function isSourceProgramDerived(sourceVar: string, content: string): boolean {
  const declarationIndex = content.lastIndexOf(`pub ${sourceVar}`);
  if (declarationIndex === -1) return false;
  const context = content.slice(Math.max(0, declarationIndex - 300), declarationIndex + 100);
  return context.includes('seeds') && context.includes('bump');
}

function resolveSourceVar(sourceVar: string, lines: string[], lineIndex: number): string {
  for (let i = Math.max(0, lineIndex - 10); i < lineIndex; i++) {
    const letMatch = lines[i].match(
      new RegExp(`let\\s+(?:mut\\s+)?${sourceVar}\\s*(?::\\s*\\w+)?\\s*=\\s*(\\w+)\\.(\\w+)`)
    );
    if (letMatch) return letMatch[1];
  }
  return sourceVar;
}

export function checkUncheckedStateOverwrite(programDir: string): Finding[] {
  
  
    const findings: Finding[] = [];
    if (!fs.existsSync(programDir)) return findings;

    console.log('[DEBUG] Scanning:', programDir);
    const rustFiles = findRustFiles(programDir);
    console.log('[DEBUG] Files found:', rustFiles);
    const seen = new Set<string>();

    

    for (const file of rustFiles) {
        const content = fs.readFileSync(file, 'utf-8');
        const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const matches = [...line.matchAll(OVERWRITE_REGEX)];

      for (const match of matches) {
        const [, targetVar, fieldName, sourceVar] = match;

        // Skip self-assignment
        if (targetVar === sourceVar) continue;

        // Skip non-critical fields
        const isCritical = CRITICAL_FIELDS.some(f => fieldName.includes(f));
        if (!isCritical) continue;

        // Skip if source is program-derived
        const resolvedSource = resolveSourceVar(sourceVar, lines, i);
        if (isSourceProgramDerived(resolvedSource, content)) continue;

        // Skip if validation exists nearby
        if (hasValidationNearby(lines, i, resolvedSource, fieldName)) continue;

        const key = `${path.basename(file)}-${i}-${targetVar}-${fieldName}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const instructionName = path.basename(file, '.rs');
        
        const isHighRisk = HIGH_RISK_SOURCES.some(s => resolvedSource.toLowerCase().includes(s));

        findings.push({
        rule: 'UNCHECKED_STATE_OVERWRITE',
        severity: isHighRisk ? 'HIGH' : 'MEDIUM',
        confidence: isHighRisk ? 'high' : 'medium',
        instruction: instructionName,
        account: targetVar,
        intent: 'protocol_storage',
        status: 'needs_manual_verification',
          attackPath: `Field '${targetVar}.${fieldName}' is overwritten from external account '${sourceVar}' without a visible equality or bounds check. If '${sourceVar}' is user-supplied, protocol invariants may be corrupted.`,
          expectedBehavior: `'${targetVar}.${fieldName}' should be validated against '${sourceVar}' before assignment — e.g. require!(${sourceVar}.${fieldName} == ${targetVar}.${fieldName})`,
          observedBehavior: `Direct overwrite: ${targetVar}.${fieldName} = ${sourceVar}.*  with no require!/assert!/validate nearby.`,
          mismatch: true,
          flowDetected: false,
          flowType: 'NONE',
          verificationSteps: [
            {
              check: 'Is the source account user-supplied or program-derived?',
              grepPattern: `pub ${sourceVar}`,
              scopedTo: instructionName,
              expected: 'context_dependent',
            },
            {
              check: 'Is there a validation function called before the overwrite?',
              grepPattern: `validate|require!|assert!`,
              scopedTo: instructionName,
              expected: 'must_exist',
            },
          ],
          claudePrompt: `In '${instructionName}', field '${targetVar}.${fieldName}' is overwritten from '${sourceVar}' with no visible validation. Check: (1) Is '${sourceVar}' user-supplied or program-derived via seeds? (2) Is there a require! or validate call within 15 lines before the assignment? (3) Could an attacker supply a mismatched '${sourceVar}' to corrupt '${targetVar}' state? This matches the Saffron H-01 tick range mismatch pattern.`,
        });
      }
    }
  }

  return findings;
}