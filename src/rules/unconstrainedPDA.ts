import { Finding } from '../types';

export function checkUnconstrainedPDA(idl: any): Finding[] {
  const findings: Finding[] = [];

  for (const instruction of idl.instructions) {
    for (const account of instruction.accounts) {
      const isPDA =
        account.pda !== undefined ||
        account.seeds !== undefined ||
        account.name.toLowerCase().includes('pda') ||
        account.name.toLowerCase().includes('vault') ||
        account.name.toLowerCase().includes('state');

      const hasConstraints =
        account.pda?.seeds !== undefined ||
        account.relations !== undefined;

      if (isPDA && !hasConstraints && account.isMut === true && account.isSigner === false) {
        findings.push({
          rule: 'UNCONSTRAINED_PDA',
          severity: 'MEDIUM',
          instruction: instruction.name,
          account: account.name,
          intent: 'protocol_storage',
          confidence: 'medium',
          status: 'needs_manual_verification',
          attackPath: `Attacker derives a malicious PDA with different seeds and passes it as '${account.name}' — no seed constraints to verify correctness.`,
          expectedBehavior: `Account '${account.name}' should have explicit seed constraints (seeds, bump) to verify it is the correct PDA.`,
          observedBehavior: `Account '${account.name}' looks like a PDA but has no seed constraints in the IDL.`,
          mismatch: true,
          verificationSteps: [
            {
              check: 'Are seeds and bump defined for this PDA in the Rust source?',
              grepPattern: `seeds.*${account.name}|${account.name}.*bump`,
              scopedTo: `${instruction.name}`,
              expected: 'must_exist',
            }
          ],
          claudePrompt: `In the '${instruction.name}' instruction, check if account '${account.name}' has seeds and bump constraints defined in the #[account(...)] macro. Without seeds, any PDA can be substituted.`,
          flowDetected: false,
          flowType: 'NONE',
        });
      }
    }
  }

  return findings;
}