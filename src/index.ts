import { program } from 'commander';
import * as fs from 'fs';
import { checkUnprotectedMutableAccount } from './rules/unprotectedMutableAccount';
import { checkUnconstrainedPDA } from './rules/unconstrainedPDA';
import { checkUnsafeCPITarget } from './rules/unsafeCPITarget';
import { checkAccountConfusion } from './rules/accountConfusion';
import { checkTokenAccountOwnerNotVerified } from './rules/tokenAccountOwnerNotVerified';
import { printConsoleReport, buildJsonReport } from './reporter';
import { detectFlowInSource } from './utils/flowDetector';
import { normalizeIDL } from './utils/idlNormalizer';
import { detectSourceProtection } from './utils/sourcePatternDetector';
import { checkUncheckedStateOverwrite } from './rules/uncheckedStateOverwrite';

program
  .name('solsentry')
  .description('Anchor IDL security linter for Solana programs')
  .argument('<idl>', 'Path to Anchor IDL JSON file')
  .option('-o, --output <file>', 'Save findings as JSON report')
  .option('-p, --programs <dir>', 'Path to Rust program source directory')
  .action((idlPath, options) => {
  const raw = JSON.parse(fs.readFileSync(idlPath, 'utf-8'));
  const idl = normalizeIDL(raw);

  // IDL-based findings
  const idlFindings = [
    ...checkUnprotectedMutableAccount(idl),
    ...checkUnconstrainedPDA(idl),
    ...checkUnsafeCPITarget(idl),
    ...checkAccountConfusion(idl),
    ...checkTokenAccountOwnerNotVerified(idl),
  ];

  // Source-based findings
  const sourceFindings = options.programs
    ? [...checkUncheckedStateOverwrite(options.programs)]
    : [];

  const allFindings = [...idlFindings, ...sourceFindings];

  // Dedup
  const seenKeys = new Set<string>();
  const dedupedFindings = allFindings.filter(f => {
  const key = `${f.rule}-${f.account}-${f.instruction}-${f.flowType}`;
  if (seenKeys.has(key)) return false;
    seenKeys.add(key);
    return true;
  });

  // Enrich with source protection and flow detection
  const enrichedFindings = dedupedFindings.map(f => {
    if (!options.programs) return f;

    const flow = detectFlowInSource(f.account, f.instruction, options.programs);
    const protection = detectSourceProtection(f.account, options.programs);

    if (
      protection.hasTokenAuthority ||
      protection.hasInterfaceType ||
      protection.hasProgramType ||
      protection.hasAddressConstraint ||
      protection.hasAdminGate
    ) {
      return {
        ...f,
        flowDetected: flow.detected,
        flowType: flow.flowType,
        severity: 'LOW' as const,
        confidence: 'low' as const,
        status: 'mitigated_in_source' as const,
      };
    }

    if (flow.flowType === 'TOKEN_TRANSFER' && f.severity === 'MEDIUM') {
      return {
        ...f,
        flowDetected: flow.detected,
        flowType: flow.flowType,
        severity: 'HIGH' as const,
        confidence: 'high' as const,
        status: 'likely_vulnerable' as const,
      };
    }

    if (flow.flowType === 'CPI' && f.rule === 'UNSAFE_CPI_TARGET') {
      return {
        ...f,
        flowDetected: flow.detected,
        flowType: flow.flowType,
        severity: 'HIGH' as const,
        confidence: 'high' as const,
        status: 'likely_vulnerable' as const,
      };
    }

    return { ...f, flowDetected: flow.detected, flowType: flow.flowType };
  });

  printConsoleReport(idl.name, enrichedFindings);

  if (options.output) {
    const report = buildJsonReport(idl.name, enrichedFindings);
    fs.writeFileSync(options.output, JSON.stringify(report, null, 2));
    console.log(`Report saved to: ${options.output}`);
  }
});

program.parse();