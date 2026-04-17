import { Finding } from './types';

export function printConsoleReport(idlName: string, findings: Finding[]): void {
  console.log(`\n╔══════════════════════════════════════╗`);
  console.log(`║         SOLSENTRY AUDIT REPORT       ║`);
  console.log(`╚══════════════════════════════════════╝`);
  console.log(`Program : ${idlName}`);
  console.log(`Findings: ${findings.length}\n`);

  if (findings.length === 0) {
    console.log('✓ No issues found.\n');
    return;
  }

  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const medCount  = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount  = findings.filter(f => f.severity === 'LOW').length;

  console.log(`Summary:`);
  console.log(`  HIGH   : ${highCount}`);
  console.log(`  MEDIUM : ${medCount}`);
  console.log(`  LOW    : ${lowCount}`);
  console.log(`─────────────────────────────────────\n`);

  for (const f of findings) {
    const icon = f.status === 'mitigated_in_source' ? '✅' : f.severity === 'HIGH' ? '🔴' : f.severity === 'MEDIUM' ? '🟡' : '🟢';
    console.log(`${icon} [${f.severity}] ${f.rule}`);
    console.log(`   Instruction      : ${f.instruction}`);
    console.log(`   Account          : ${f.account}`);
    console.log(`   Status           : ${f.status}`);
    console.log(`   Confidence       : ${f.confidence}`);
    console.log(`   Attack Path      : ${f.attackPath}`);
    console.log(`   Expected         : ${f.expectedBehavior}`);
    console.log(`   Observed         : ${f.observedBehavior}`);
    console.log(`   Claude Prompt    : ${f.claudePrompt}`);
    console.log(`   Flow Detected   : ${f.flowDetected ? '⚡ YES — transfer operation found' : 'No'}`);
    console.log(`   Flow Type       : ${f.flowType}`);
    console.log();
  }
}

export function buildJsonReport(idlName: string, findings: Finding[]): object {
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const medCount  = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount  = findings.filter(f => f.severity === 'LOW').length;

  return {
    program: idlName,
    generatedAt: new Date().toISOString(),
    summary: {
      total: findings.length,
      high: highCount,
      medium: medCount,
      low: lowCount,
    },
    findings: findings.map(f => ({
      rule: f.rule,
      severity: f.severity,
      instruction: f.instruction,
      account: f.account,
      intent: f.intent,
      confidence: f.confidence,
      status: f.status,
      attackPath: f.attackPath,
      expectedBehavior: f.expectedBehavior,
      observedBehavior: f.observedBehavior,
      mismatch: f.mismatch,
      verificationSteps: f.verificationSteps,
      claudePrompt: f.claudePrompt,
    }))
  };
}