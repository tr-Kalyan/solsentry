# DeFi Security Patterns — SolSentry Reference

## Slippage Protection
Every instruction moving tokens on behalf of a user MUST include a 
user-controlled minimum output parameter.

What counts as protection:
- min_amount_out, minimum_amount_out, other_amount_threshold (Orca style)
- sqrt_price_limit as price bound  
- Any user-set parameter that causes revert if output is insufficient

What does NOT count:
- Protocol-internal checks not exposed as instruction parameter
- Admin-configurable limits

NAV-locking exception (vault/fund protocols):
Check for all three: withdraw_amount locked into request struct at submission,
set_nav rate-limited (e.g. ±0.05% per update), settlement divergence check.
If all three present: slippage is mitigated BUT flag separate FUND_LOCKUP risk —
if NAV never returns to tolerance band, user funds locked indefinitely.

Real finding: SolvBTC vault_deposit (OffSide Labs Oct 2025) — no min_shares parameter

## Reward Accounting

### Double Claim
unstake_locked must subtract reward_debt before paying rewards.
Flag: unstake instruction transfers rewards without checking reward_debt.
Real finding: StakeFlow F-01 — unstake_locked ignores reward_debt entirely.

### Reward Inflation via Truncation  
partial_unstake scaling reward_debt proportionally using integer division
causes truncation — reward_debt becomes lower than actual paid amount,
allowing repeated extraction via partial_unstake → claim_rewards loop.
Flag: reward_debt * remaining / total without settling rewards first.
Real finding: StakeFlow F-02 — ~99x reward extraction via 499 cycles.
Fix: settle all pending rewards before reducing position, then reset debt to 0.

### Permissionless Accumulation Loss
Three signals required simultaneously:
1. Instruction has no signer (permissionless)
2. Instruction resets a timestamp (last_update_timestamp, last_accrual)
3. Instruction performs integer or safe_div on reward/rate/emission field
Attacker calls at high cadence — each micro-call loses fractional rewards
that are never recovered due to truncation + timestamp reset.
Real finding: Jupiter Lend update_rate (niffylord M-05, confirmed Medium)

### Retroactive Rate Change
reward_rate updated without advancing global index first — affects ALL
historical unpaid rewards. Rate decrease after claim causes underflow DoS.
Fix: use global accumulated reward index with per-position checkpoint.
Real finding: StakeFlow F-06

## Exchange Rate Manipulation — Liquid Staking
Liquid staking mints receipt tokens directly to user wallet.
User can burn tokens externally to manipulate supply-based exchange rate.
First depositor attack: stake 1001 → burn 1000 → victim stakes 500 → gets 0.
Fix: mint dead shares on first deposit to prevent supply collapsing to near-zero.
Real finding: StakeFlow F-04

## Missing Deadline Parameter
Swap instructions without expiry/deadline argument — valid signed transaction
can sit in mempool for hours and execute at stale price even with slippage set.
Both slippage AND deadline are required for complete swap protection.

## Oracle Safety
- Price cache TTL must be enforced — stale prices cause incorrect liquidations
- Staleness rejection required on every price consumption
- Circuit breaker on large price moves (e.g. 20% threshold)
- Fallback cascade ordering must be verified (manual override → custom → reflector → fallback)
- Flash loan manipulation: TWAP is manipulation-resistant, spot price is not
