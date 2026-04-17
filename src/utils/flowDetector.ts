import * as fs from 'fs';
import * as path from 'path';

const TRANSFER_PATTERNS = [
  'token::transfer',
  'transfer_checked',
  'invoke(',
  'invoke_signed(',
  'transfer_to',
  'transfer_token_from_pool_authority',
  'transfer_lamports_from_user',
  'transfer_lamports_from_pool_account',
  'transfer_token_from',
];

const TRANSFER_REGEX = /token::transfer|transfer_checked|invoke\s*\(|invoke_signed\s*\(|transfer_token|transfer_lamports/;
const CPI_REGEX = /invoke_signed\s*\(/;

export type FlowType = 'TOKEN_TRANSFER' | 'CPI' | 'NONE';

export interface FlowResult {
  detected: boolean;
  flowType: FlowType;
}

export function detectFlowInSource(
  accountName: string,
  instructionName: string,
  programDir: string
): FlowResult {
  if (!fs.existsSync(programDir)) {
    return { detected: false, flowType: 'NONE' };
  }

  const rustFiles = findRustFiles(programDir);

  for (const file of rustFiles) {
    const content = fs.readFileSync(file, 'utf-8');
    const block = extractInstructionBlock(content, instructionName);
    if (!block) continue;

    const hasAccount = block.includes(accountName);
    if (!hasAccount) continue;

    const hasTransfer = TRANSFER_REGEX.test(block);
    const hasCPI = CPI_REGEX.test(block);

    if (hasTransfer) return { detected: true, flowType: 'TOKEN_TRANSFER' };
    if (hasCPI)      return { detected: true, flowType: 'CPI' };
    if (!hasTransfer && !hasCPI) {
        const wholeFileTransfer = TRANSFER_REGEX.test(content);
        const wholeFileCPI = CPI_REGEX.test(content);
        if (wholeFileTransfer) return { detected: true, flowType: 'TOKEN_TRANSFER' };
        if (wholeFileCPI) return { detected: true, flowType: 'CPI' };
    }
  }

  return { detected: false, flowType: 'NONE' };
}

function findRustFiles(dir: string): string[] {
  const results: string[] = [];

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findRustFiles(fullPath));
    } else if (entry.name.endsWith('.rs')) {
      results.push(fullPath);
    }
  }

  return results;
}

function extractInstructionBlock(
  content: string,
  instructionName: string
): string | null {
  // Find function matching instruction name
  const fnIndex = content.indexOf(`fn ${instructionName}`);
  if (fnIndex === -1) return null;

  // Extract from function start to matching closing brace
  let depth = 0;
  let started = false;
  let start = fnIndex;

  for (let i = fnIndex; i < content.length; i++) {
    if (content[i] === '{') {
      depth++;
      started = true;
    } else if (content[i] === '}') {
      depth--;
      if (started && depth === 0) {
        return content.slice(start, i + 1);
      }
    }
  }

  return null;
}