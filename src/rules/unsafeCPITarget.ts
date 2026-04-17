import { Finding } from '../types';

const KNOWN_SAFE_PROGRAMS = new Set([
  'systemProgram', 'system_program',
  'tokenProgram', 'token_program',
  'associatedTokenProgram', 'associated_token_program',
  'rent', 'clock', 'instructions',
  'token2022Program', 'token_2022_program',
]);

export function checkUnsafeCPITarget(idl: any): Finding[] {
  const findings: Finding[] = [];

  for (const instruction of idl.instructions) {
    for (const account of instruction.accounts) {
      const isProgram =
        account.name.toLowerCase().includes('program') ||
        account.type === 'programId';

      const isUnknownProgram =
        isProgram &&
        !KNOWN_SAFE_PROGRAMS.has(account.name) &&
        account.isSigner === false;

      if (isUnknownProgram) {
        findings.push({
          rule: 'UNSAFE_CPI_TARGET',
          severity: 'HIGH',
          instruction: instruction.name,
          account: account.name,
          intent: 'unknown',
          confidence: 'medium',
          status: 'needs_manual_verification',
          attackPath: `Attacker substitutes a malicious program for '${account.name}' — no constraint pins it to a known program ID. The CPI call executes attacker-controlled code.`,
          expectedBehavior: `Account '${account.name}' should be constrained to a known program ID via constraint = ${account.name}.key() == EXPECTED_PROGRAM_ID.`,
          observedBehavior: `Account '${account.name}' is passed as a CPI target with no program ID verification.`,
          mismatch: true,
          verificationSteps: [
            {
              check: 'Is the program ID verified against a known constant?',
              grepPattern: `${account.name}.*key\\(\\)|require.*${account.name}`,
              scopedTo: `${instruction.name}`,
              expected: 'must_exist',
            }
          ],
          claudePrompt: `In the '${instruction.name}' instruction, check if '${account.name}' is validated against a known program ID in the Rust source. Look for constraint = ${account.name}.key() == SOME_PROGRAM_ID or a require! check. If absent, any program can be invoked.`,
          flowDetected: false,
          flowType: 'NONE',
        });
      }
    }
  }

  return findings;
}