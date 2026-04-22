import { Finding } from "../types";

const SWAP_PATTERNS = [
  'swap', 'exchange', 'trade', 'convert', 'route'
];

const LIQUIDITY_PATTERNS = [
  'deposit', 'withdraw', 'add_liquidity', 'remove_liquidity',
  'provide_liquidity', 'supply', 'redeem', 'mint_lp'
];

const SLIPPAGE_GUARD_PATTERNS = [
  'min_out', 'min_amount_out', 'minimum_out', 'min_receive',
  'min_tokens_out', 'minimum_tokens', 'min_return',
  'max_in', 'max_amount_in', 'maximum_in', 'slippage',
  'slippage_bps', 'min_shares', 'minimum_shares',
  'min_lp', 'min_lp_tokens', 'minimum_lp',
  'minimum_amount_out', 'minimum_amount_in',
  'minimum_token', 'maximum_token',
  'amount_out_minimum', 'amount_in_maximum',
  'min_out_amount', 'max_in_amount',
  'other_amount_threshold', 'amount_threshold',
  'sqrt_price_limit'
];

function getMovementType(name: string): 'swap' | 'liquidity' | null {
    const lower = name.toLowerCase();
    if (SWAP_PATTERNS.some(p => lower.includes(p))) return 'swap';
    if (LIQUIDITY_PATTERNS.some(p => lower.includes(p))) return 'liquidity';
    return null;
}

function resolveFields(arg: any, idl: any, depth: number = 0): string[] {
  // Prevent infinite recursion on circular types
  if (depth > 3) return [];

  const fields: string[] = [];

  // Direct arg name
  if (arg.name) fields.push(arg.name.toLowerCase());

  // If type is a defined struct, recurse into its fields
  const typeName = arg.type?.defined?.name || arg.type?.defined;
  if (typeName && idl.types) {
    const typeDef = idl.types.find((t: any) => t.name === typeName);
    if (typeDef?.type?.fields) {
      for (const field of typeDef.type.fields) {
        fields.push(...resolveFields(field, idl, depth + 1));
      }
    }
  }

  return fields;
}

function hasSlippageGuard(args: any[], idl: any): boolean {
  if (!args || args.length === 0) return false;
  for (const arg of args) {
    const allNames = resolveFields(arg, idl);
    for (const name of allNames) {
      if (SLIPPAGE_GUARD_PATTERNS.some(guard => name.includes(guard))) {
        return true;
      }
    }
  }
  return false;
}

export function checkMissingSlippageParameter(idl: any): Finding[] {
  const findings: Finding[] = [];

  for (const instruction of idl.instructions || []) {
    const movementType = getMovementType(instruction.name);
    if (!movementType) continue;

    const args = instruction.args || [];
    if (hasSlippageGuard(args, idl)) continue;

    const isSwap = movementType === 'swap';
    const argNames = args.map((a: any) => a.name).join(', ') || 'none';

    findings.push({
      rule: 'MISSING_SLIPPAGE_PARAMETER',
      severity: isSwap ? 'HIGH' : 'MEDIUM',
      instruction: instruction.name,
      account: 'N/A',
      intent: 'unknown',
      confidence: isSwap ? 'high' : 'medium',
      status: 'needs_manual_verification',
      attackPath: isSwap
        ? `MEV bot sandwiches '${instruction.name}': buys before tx to move price, lets tx execute at worse rate, sells after. User has no on-chain minimum to reject bad execution.`
        : `User calls '${instruction.name}' without a minimum output guarantee. If price or oracle moves between submission and execution, user receives fewer shares/tokens than expected.`,
      expectedBehavior: `'${instruction.name}' should include a parameter such as 'min_amount_out', 'min_shares', or 'slippage_bps' that causes the instruction to revert if output is below user expectation.`,
      observedBehavior: `No slippage guard found in args: [${argNames}]`,
      mismatch: true,
      verificationSteps: [
        {
          check: 'Inline require! slippage check in instruction body',
          grepPattern: `require!.*${instruction.name}|assert!.*min.*out`,
          scopedTo: `src/instructions/${instruction.name}.rs`,
          expected: 'context_dependent',
        },
        {
          check: 'Slippage enforced by router/wrapper contract upstream',
          grepPattern: `min_amount_out|slippage`,
          scopedTo: 'src/',
          expected: 'context_dependent',
        },
      ],
      claudePrompt: `In '${instruction.name}', no slippage protection parameter exists in the IDL args [${argNames}]. Check the Rust source: (1) Is there a require! comparing output to a minimum inside the instruction? (2) Is slippage enforced by a caller/router? (3) For vault/fund protocols: check if a nav/price field is snapshotted into a request struct at submission time — if present, NAV-locking is an alternative slippage mechanism. Also check if the NAV setter is rate-limited (e.g. set_nav with bps bounds). If both exist, downgrade to INFO but flag a separate concern: check the protocol documentation for the withdrawal settlement condition. If settlement only executes when NAV stays within a tolerance band (e.g. ±1%), user funds may be locked indefinitely if NAV moves permanently outside that range — this is a separate FUND_LOCKUP risk, not a slippage issue. If none of the above, users are exposed to MEV sandwich attacks with no on-chain recourse.`,
      flowDetected: false,
      flowType: 'NONE',
    });
  }

  return findings;
}