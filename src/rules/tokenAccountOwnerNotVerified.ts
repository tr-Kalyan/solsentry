import { Finding } from '../types';

export function checkTokenAccountOwnerNotVerified(idl: any): Finding[] {
  const findings: Finding[] = [];

  for (const instruction of idl.instructions) {
    const hasSigner = instruction.accounts.some((a: any) => a.isSigner === true);

    const tokenAccounts = instruction.accounts.filter((a: any) => {
      const isTokenType = a.type?.defined === 'TokenAccount';
      const isTokenByName =
        a.name.toLowerCase().includes('token') &&
        !a.name.toLowerCase().includes('program') &&
        !a.name.toLowerCase().includes('mint');
      return (isTokenType || isTokenByName) && a.isMut === true;
    });

    for (const ta of tokenAccounts) {
      const ix = instruction.name.toLowerCase();
      const name = ta.name.toLowerCase();

      let intent: Finding['intent'] = 'unknown';
      if ((ix.includes('withdraw') || ix.includes('borrow') || ix.includes('claim')) &&
          (name.includes('user') || name.includes('recipient') || name.includes('destination'))) {
        intent = 'user_destination';
      } else if (name.includes('vault') || name.includes('pool') || name.includes('reserve')) {
        intent = 'protocol_storage';
      }

      if (intent === 'protocol_storage') continue;

      const hasOwnerConstraint =
        ta.relations !== undefined ||
        ta.constraints !== undefined;

      if (!hasOwnerConstraint && hasSigner) {
        findings.push({
          rule: 'TOKEN_ACCOUNT_OWNER_NOT_VERIFIED',
          severity: intent === 'user_destination' ? 'HIGH' : 'MEDIUM',
          instruction: instruction.name,
          account: ta.name,
          intent,
          confidence: intent === 'user_destination' ? 'high' : 'medium',
          status: intent === 'user_destination' ? 'likely_vulnerable' : 'needs_manual_verification',
          attackPath: `Attacker replaces '${ta.name}' with their own token account — no owner constraint binds it to the signer. Funds redirected to attacker. Matches Enclave C-01 pattern.`,
          expectedBehavior: `Token account '${ta.name}' owner must equal the signer's public key.`,
          observedBehavior: `Token account '${ta.name}' is mutable with no owner constraint tying it to the signer.`,
          mismatch: true,
          verificationSteps: [
            {
              check: 'Does the instruction verify token account owner equals user?',
              grepPattern: `${ta.name}.*owner|owner.*${ta.name}`,
              scopedTo: instruction.name,
              expected: 'must_exist',
            },
            {
              check: 'Is the token account constrained to the user ATA?',
              grepPattern: `get_associated_token_address|associated_token`,
              scopedTo: instruction.name,
              expected: 'context_dependent',
            }
          ],
          claudePrompt: `In the '${instruction.name}' instruction, check if '${ta.name}' has a constraint verifying its owner equals the signer. Look for: constraint = ${ta.name}.owner == user.key(), has_one = owner, or ATA derivation. If absent, an attacker can pass their own token account and steal funds.`,
          flowDetected: false,
          flowType: 'NONE',
        });
      }
    }
  }

  return findings;
}