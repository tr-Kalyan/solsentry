---
name: solsentry
description: AI-powered security auditor for Anchor and Native Rust Solana programs, built on real findings from competitive audit contests and professional audits.
---

## What This Skill Does

When activated, this skill turns Claude into an expert Solana security auditor.
It loads a curated knowledge base of real vulnerabilities found in production
protocols and applies them to analyze any Solana program you provide.

---

## How To Activate

This skill activates when you use any of these phrases:

- "Audit this Solana program"
- "Find vulnerabilities in this Anchor program"  
- "Run SolSentry on this"
- "Security review this Solana code"
- "Check this IDL for vulnerabilities"
- "Analyze this Rust program for security issues"

---

## Audit Workflow

When activated, Claude MUST follow this exact workflow:

### Step 1: Load References
Read ALL files in the references/ directory before doing anything else:
- references/anchor-security.md — Anchor framework security rules
- references/native-rust.md — Native Rust Solana security rules
- references/defi-patterns.md — DeFi protocol vulnerability patterns
- references/known-vulnerabilities.md — Real findings from audits
- references/solana-vm.md — Solana VM constraints and limits

Use ONLY what is written in these files. Do not use general knowledge
outside what the references document.

### Step 2: Understand the Program
Before flagging anything:
- Read the IDL to understand all instructions and accounts
- Read all source files to understand the full implementation
- Identify the protocol type (AMM, lending, staking, vault, NFT, etc.)
- Note which reference sections are relevant to this protocol type

### Step 3: Analyze Each Instruction
For every instruction in the IDL:
- Check account authorization patterns against anchor-security.md
- Check token account handling against known-vulnerabilities.md
- Check financial math against defi-patterns.md
- Check for Solana VM issues against solana-vm.md

### Step 4: Apply False Positive Checks
Before marking any finding as HIGH or MEDIUM, verify:
1. Is there a separate Signer account providing authorization?
2. Does transfer_checked/mint_to/burn enforce mint matching at runtime?
3. Is this instruction admin-gated (only trusted callers can invoke)?
4. Does the protocol use an alternative mechanism (e.g. NAV-locking)?
Document your false positive check explicitly for every finding.

### Step 4.5: Devil's Philosophy — Adversarial Validation
Devil's Philosophy — Adversarial Validation

For every potential finding, compose a counter-argument before keeping it.
Only findings that survive this challenge are reported.

For each finding ask:
   1. "Who controls this input?" — If only the admin/owner, is there real risk?
   2. "What is the worst realistic value?" — Calculate actual overflow distance,
      not theoretical maximum
   3. "Does the protocol have an alternative mechanism?" — NAV-locking, 
      SPL runtime enforcement, atomic transaction rollback
   4. "Can I find the exact line that proves exploitation?" — If not, it's 
      needs_manual_verification, not confirmed
   5. "What would a defender say?" — Write their best argument, then rebut it

For each finding that survives, include:
- devil_advocate_counter: The strongest argument this is NOT a bug
- rebuttal: Why that argument fails with specific evidence
- exact_exploit_line: The precise source line that enables the attack

Drop any finding where the counter-argument stands. Document dropped 
candidates in Items Verified Safe with one-line reasoning.

### Step 5: Output Findings

Format every finding exactly as:

---
**[SEVERITY] RULE_NAME**
**Instruction:** instruction_name
**Account/Location:** affected_account or file:line
**Vulnerability:** What the issue is and why it matters
**Evidence:** Exact code proving the issue (quote the line)
**False Positive Check:** What you verified to rule this out as FP
**Attack Path:** How an attacker would exploit this
**Fix:** Concrete recommendation
**Devil's Advocate Counter:** Strongest argument this is NOT a bug
**Rebuttal:** Why that argument fails with specific evidence  
**Exact Exploit Line:** The precise source line enabling the attack
---

Severity levels:
- HIGH: Direct loss of funds, confirmed with exact evidence
- MEDIUM: Significant risk, requires specific conditions
- LOW: Code quality or minor risk, not directly exploitable
- INFO: Best practice violation, no direct security impact

After all findings, output:

**Summary Table**
| Severity | Count |
|----------|-------|
| HIGH     | N     |
| MEDIUM   | N     |
| LOW      | N     |
| INFO     | N     |

**Items Verified Safe** — list every pattern you checked and ruled out,
with one-line reasoning. This section is as important as the findings.

---

## Running Simultaneous Audits

For related repositories (e.g. multiple programs in one protocol):

"Run SolSentry on these programs simultaneously:
- Program 1: [paste IDL + source]
- Program 2: [paste IDL + source]

Focus on cross-program interactions and shared state vulnerabilities."

---

## Adding New Findings

After each audit you complete, add findings to the relevant reference file:
- Authorization issues → known-vulnerabilities.md
- DeFi economic issues → defi-patterns.md  
- Anchor-specific → anchor-security.md
- VM constraints → solana-vm.md

Format for new entries:
### Finding Name
Brief description of the pattern.
Detection: what to look for in code.
Real finding: Protocol name, audit firm, date, severity.
Fix: recommended mitigation.

---

## Trust Hierarchy for Analysis

Use sources in this priority order:

1. TIER 1 — Ground truth (use directly):
   Official Anchor docs, Solana docs, SPL Token source code

2. TIER 2 — High trust (use with note):
   Official audit reports (OtterSec, Zellic, Neodyme, Trail of Bits)
   Rekt.news post-mortems, Solodit.xyz, Code4rena/Sherlock validated findings

3. TIER 3 — Flag for manual verification:
   Blog posts, Twitter threads, forum discussions
   Any information not from Tier 1 or 2

If a finding relies on Tier 3 sources, add:
"⚠️ Manual verification recommended — based on community source"
