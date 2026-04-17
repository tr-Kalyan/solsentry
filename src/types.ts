export type IntentType =
  | 'user_destination'
  | 'protocol_storage'
  | 'protocol_fee'
  | 'user_source'
  | 'unknown';



export interface VerificationStep {
  check: string;
  grepPattern: string;
  scopedTo: string;
  expected: 'must_exist' | 'must_not_exist' | 'context_dependent';
}

export type FindingStatus =
  | 'likely_vulnerable'
  | 'needs_manual_verification'
  | 'requires_protocol_understanding'
  | 'mitigated_in_source';

export interface Finding {
  rule: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  instruction: string;
  account: string;
  intent: IntentType;
  confidence: 'high' | 'medium' | 'low';
  status: FindingStatus;
  attackPath: string;
  expectedBehavior: string;
  observedBehavior: string;
  mismatch: boolean;
  verificationSteps: VerificationStep[];
  claudePrompt: string;
  flowDetected: boolean;
  flowType: 'TOKEN_TRANSFER' | 'CPI' | 'NONE';
}