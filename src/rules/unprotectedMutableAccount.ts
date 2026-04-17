
import { Finding } from '../types';

const PROGRAM_OWNED_PATTERNS = [
  'vault', 'pool', 'state', 'reserve', 'market',
  'position', 'config', 'treasury', 'escrow'
];

const USER_ACCOUNT_PATTERNS = [
  'user', 'owner', 'authority', 'payer',
  'signer', 'admin', 'manager', 'recipient'
];

function isProgramOwned(name: string): boolean {
  return PROGRAM_OWNED_PATTERNS.some(p => name.toLowerCase().includes(p));
}

function isUserAccount(name: string): boolean {
  return USER_ACCOUNT_PATTERNS.some(p => name.toLowerCase().includes(p));
}

function hasVisibleProtection(account: any): boolean {
  return (
    account.isSigner === true ||
    account.type?.defined !== undefined ||
    account.pda?.seeds !== undefined ||
    account.seeds !== undefined ||
    account.relations !== undefined
  );
}

export function checkUnprotectedMutableAccount(idl: any): Finding[] {
  const findings: Finding[] = [];

  for (const instruction of idl.instructions) {
    const instructionHasSigner = instruction.accounts.some(
      (a: any) => a.isSigner === true
    );

    for (const account of instruction.accounts) {
      if (!account.isMut) continue;
      if (account.isSigner === true) continue;
      if (hasVisibleProtection(account)) continue;

      const isProgOwned = isProgramOwned(account.name);
      const isUserAcc   = isUserAccount(account.name);

      // User account not signing — HIGH, clear bug
      if (isUserAcc) {
        findings.push({
          rule: 'UNPROTECTED_MUTABLE_ACCOUNT',
          severity: 'HIGH',
          instruction: instruction.name,
          account: account.name,
          intent: 'unknown',
          confidence: 'high',
          status: 'likely_vulnerable',
          attackPath: `'${account.name}' looks like a user/authority account but is not required to sign. Anyone can pass this account and authorize writes on behalf of any user.`,
          expectedBehavior: `'${account.name}' should be Signer<'info> to require transaction authorization from the actual owner.`,
          observedBehavior: `'${account.name}' is mutable but isSigner is false — no visible authorization.`,
          mismatch: true,
          verificationSteps: [
            {
              check: 'Is this account typed as Signer in the Rust source?',
              grepPattern: `${account.name}.*Signer|Signer.*${account.name}`,
              scopedTo: instruction.name,
              expected: 'must_exist',
            }
          ],
          claudePrompt: `In the '${instruction.name}' instruction, account '${account.name}' looks like a user or authority account but is not marked as a signer in the IDL. Open the Rust source for this instruction and check: (1) Is it typed as Signer<'info>? (2) Is there a has_one constraint linking it to another signer? (3) Is there a require! check verifying the caller? If none of these exist, this is a confirmed missing signer vulnerability.`,
          flowDetected: false,
          flowType: 'NONE',
        });
        continue;
      }

      // Program-owned account with no visible constraint
      // Could still be protected via runtime require! — needs verification
      if (isProgOwned || !instructionHasSigner) {
        findings.push({
          rule: 'UNPROTECTED_MUTABLE_ACCOUNT',
          severity: 'MEDIUM',
          instruction: instruction.name,
          account: account.name,
          intent: 'protocol_storage',
          confidence: isProgOwned ? 'medium' : 'high',
          status: isProgOwned ? 'needs_manual_verification' : 'likely_vulnerable',
          attackPath: isProgOwned
            ? `'${account.name}' is a mutable program-owned account with no visible IDL constraint. If no runtime require! or typed Account<> exists in source, attacker can substitute any account.`
            : `'${account.name}' is mutable and the instruction has no signer at all — no authorization mechanism visible.`,
          expectedBehavior: `'${account.name}' should be protected via Account<'info, T> typing, seeds+bump, has_one, or runtime require! check.`,
          observedBehavior: `'${account.name}' is mutable with no authorization constraint visible in IDL.`,
          mismatch: true,
          verificationSteps: [
            {
              check: 'Is account typed as Account<> or protected by seeds/has_one?',
              grepPattern: `${account.name}.*Account<|has_one.*${account.name}|seeds.*${account.name}`,
              scopedTo: instruction.name,
              expected: 'must_exist',
            },
            {
              check: 'Is there a runtime require! check in the instruction body?',
              grepPattern: `require!.*${account.name}|${account.name}.*owner`,
              scopedTo: instruction.name,
              expected: 'context_dependent',
            }
          ],
          claudePrompt: `In the '${instruction.name}' instruction, account '${account.name}' is mutable with no authorization constraint visible in the IDL. Open the Rust source and check: (1) Is it typed as Account<'info, SomeStruct>? (2) Does it have seeds+bump constraints? (3) Is there a has_one linking it to an authority? (4) Is there a require! check in the instruction body verifying ownership? Confirm vulnerable or mitigated with the exact line reference.`,
          flowDetected: false,
          flowType: 'NONE',
        });
      }
    }
  }

  return findings;
}