import { Finding } from '../types';

export function checkAccountConfusion(idl: any): Finding[] {
  const findings: Finding[] = [];

  const programAccountTypes = new Set(
    idl.accounts?.map((a: any) => a.name.toLowerCase()) ?? []
  );

  for (const instruction of idl.instructions) {
    const seen = new Set<string>();

    for (const account of instruction.accounts) {
      if (seen.has(account.name)) {
        findings.push({
          rule: 'ACCOUNT_CONFUSION',
          severity: 'HIGH',
          instruction: instruction.name,
          account: account.name,
          intent: 'unknown',
          confidence: 'high',
          status: 'likely_vulnerable',
          attackPath: `Attacker passes the same account for two different roles in '${instruction.name}', potentially bypassing validation logic.`,
          expectedBehavior: `Each account in '${instruction.name}' should be a distinct account with a unique role.`,
          observedBehavior: `Account '${account.name}' appears more than once in instruction '${instruction.name}'.`,
          mismatch: true,
          verificationSteps: [
            {
              check: 'Does the instruction use the same account for two different roles?',
              grepPattern: `${account.name}`,
              scopedTo: `${instruction.name}`,
              expected: 'context_dependent',
            }
          ],
          claudePrompt: `In the '${instruction.name}' instruction, account '${account.name}' appears twice. Check the Rust source to see if these are meant to be distinct accounts and whether passing the same account for both roles could bypass any validation.`,
          flowDetected: false,
          flowType: 'NONE',
        });
      }
      seen.add(account.name);

      const suggestsDataAccount =
        programAccountTypes.has(account.name.toLowerCase()) ||
        account.name.toLowerCase().includes('config') ||
        account.name.toLowerCase().includes('market') ||
        account.name.toLowerCase().includes('pool') ||
        account.name.toLowerCase().includes('position');

      const hasTypeConstraint = account.type?.defined !== undefined;

      if (suggestsDataAccount && !hasTypeConstraint && account.isSigner === false) {
        findings.push({
          rule: 'ACCOUNT_CONFUSION',
          severity: 'MEDIUM',
          instruction: instruction.name,
          account: account.name,
          intent: 'unknown',
          confidence: 'medium',
          status: 'needs_manual_verification',
          attackPath: `Attacker passes a different account type for '${account.name}' — no type constraint prevents substitution.`,
          expectedBehavior: `Account '${account.name}' should be typed as a specific struct to enforce correct account type.`,
          observedBehavior: `Account '${account.name}' suggests a typed data account but has no type constraint.`,
          mismatch: true,
          verificationSteps: [
            {
              check: 'Is this account typed as Account<> in the Rust source?',
              grepPattern: `${account.name}.*Account<`,
              scopedTo: `${instruction.name}`,
              expected: 'must_exist',
            }
          ],
          claudePrompt: `In the '${instruction.name}' instruction, check if account '${account.name}' is typed as Account<'info, SomeStruct> in the Rust source. If it is AccountInfo with no type, the program cannot distinguish between different account types.`,
          flowDetected: false,
          flowType: 'NONE',
        });
      }
    }
  }

  return findings;
}