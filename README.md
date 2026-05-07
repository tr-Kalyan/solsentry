# SolSentry — Solana Security Audit Skill

AI-powered security auditor for Anchor and Native Rust Solana programs.
Built on real findings from competitive audit contests and professional audits.

## Install

### Claude.ai
1. Download solsentry.skill from Releases
2. Claude.ai → Settings → Skills → Upload
3. Say "Audit this Solana program" and paste your code

### Cursor IDE
```bash
mkdir -p ~/.cursor/skills
git clone https://github.com/tr-Kalyan/solsentry.git ~/.cursor/skills/solsentry
```
Then: "Use the solsentry skill. Audit this program: [paste code]"

### Claude Code (CLI)
```bash
git clone https://github.com/tr-Kalyan/solsentry.git
```
Open Claude Code in the solsentry directory. Say:
"Use SKILL.md as your audit workflow. Audit this program: [paste IDL + source]"

## Usage

Paste your IDL and source code with any of these triggers:
- "Audit this Solana program"
- "Run SolSentry on this"
- "Find vulnerabilities in this Anchor program"

## Adding New Findings

After reading an audit report or finding a bug:
1. Open the relevant references/*.md file
2. Add a new section with: description, detection signal, real finding reference, fix
3. Commit — skill is immediately updated for all users

## Knowledge Base

| File | Contents |
|------|----------|
| references/anchor-security.md | Anchor constraints, account types, footguns |
| references/native-rust.md | Native Rust validation sequence, CPI patterns |
| references/defi-patterns.md | Slippage, oracle, staking, liquidation patterns |
| references/known-vulnerabilities.md | Real findings from production audits |
| references/solana-vm.md | Stack limits, compute budget, rent, atomicity |

## Credits
Reference content includes material from Frank Castle's safe-solana-builder (MIT).
Real findings from: Jupiter Lend, SolvBTC, Raydium, Orca, LimitBreak, Jito, StakeFlow.
