# Known Vulnerability Patterns — SolSentry Reference

## Authorization Failures

### Missing Account Ownership Check (Enclave C-01 pattern)
Token accounts passed without owner verification — attacker substitutes
account they control with correct mint but wrong owner.
Detection: mutable token account with no has_one, no token::authority,
no seeds constraint AND no token::mint binding in same account block.
AND no transfer_checked/mint_to/burn with pinned mint in instruction body.

### Close Without Ownership Check
close = recipient on account without has_one or seeds linking account to signer.
Attacker can close any user's zero-balance account and steal rent lamports.
Real finding: MetaLend capstone close_user_deposit — any signer can close any account.
Fix: add has_one = user and seeds = [b"prefix", user.key()] to account constraint.

### Unsafe Remaining Accounts
remaining_accounts bypasses all Anchor type safety.
mem::transmute on remaining_accounts[N] to forge a typed account is critical.
Real finding: MetaLend flash_loan.rs:37 — transmute on remaining_accounts[1]
to forge fake token program, bypassing SPL transfer entirely.
Detection: mem::transmute appearing in same function as remaining_accounts usage.

### Unsafe CPI Target
Program account used as CPI target without ID verification.
Detection: UncheckedAccount or AccountInfo used as program in CPI without
require_keys_eq! against a hardcoded constant before the CPI call.

## Accounting Drift

### RAW vs NET Debt Asymmetry (Jupiter Lend, Code4rena April 2026)
total_borrow during liquidation uses RAW debt (including dust) but normal
accounting uses NET debt (excluding dust). Dead variable absorbed_dust_debt
confirmed the asymmetry was known but unresolved.
Submitted Medium, corroborated by dead variable evidence.

## Economic Vulnerabilities

### Reward Sandwich (Jito Restaking pattern)
Deposit instruction updates reward index AFTER updating total balance.
Attacker deposits just before large reward arrives, claims disproportionate share.
All five Jito HIGH findings were the same root cause.
Fix: update reward index with pre-deposit total_supply, then accept deposit.

### LimitBreak AMM WETH Unwrap Asymmetry
_distributeOrCollectLiquidityToken has no try/catch on ETH path but graceful
ERC20 fallback. WETH unwrap failure permanently blocks liquidity operations.
Confirmed Medium, payout pending post-contest processing.

## Solana-Specific

### Stack Overflow in Large Account Structs (StakeFlow F-05)
Anchor structs with 5+ unboxed InterfaceAccount fields exceed 4096-byte limit.
Program compiles but instructions permanently revert at runtime.
Detection: count InterfaceAccount<'info occurrences in single #[derive(Accounts)]
block — if >= 5 and none wrapped in Box<>, flag HIGH.
Fix: Box<InterfaceAccount<'info, TokenAccount>> for large fields.

### LayerZero BlockedMessageLib Default Send (Code4rena April 2026)
BlockedMessageLib settable as default send library with no grace period,
unlike the receive path which has protection. Three README statements confirmed
the asymmetry was an intentional security property that was violated.
Confirmed Medium.

## Math Bounds & Accounting Drift

### Broken Safety Cap Causes Liquidation DoS (Jupiter Lend S-27)
Protocol caps debt_per_col at 1e26 to prevent precision loss, but the cap is
2x too high. The downstream conversion to ratioX48 format overflows MAX_RATIOX48
(~1.30e25) before the liquidation threshold multiplier is applied.

Root cause: cap was calculated for raw_col_per_debt (inverse path) but applied
to debt_per_col (forward path) — different downstream bounds.

Detection: Look for a hardcoded cap on a ratio/price variable that is then
multiplied by a constant before being passed to a tick/price math function.
Verify: cap * multiplier_constant / divisor <= downstream_max_value.

Attack path: When collateral price collapses or debt price spikes, debt_per_col
enters range [4.62e25, 1e26]. Cap does not activate. liquidation_ratio overflows
MAX_RATIOX48. All liquidations revert permanently. Bad debt accumulates.

Real finding: Jupiter Lend S-27, Code4rena Feb 2026. Confirmed Medium.
Conditions required are extreme but deterministic — not a probabilistic edge case.

Fix: Derive cap from MAX_RATIOX48 working backwards:
  cap ≤ MAX_RATIOX48 × 1e15 / 2^48 × 1000 / LML_max ≈ 4.62e25

### Stale dust_debt_raw Inflates total_borrow After Partial Liquidation (Jupiter Lend)
fetch_latest_position() recalculates debt_raw and col_raw from branch debt
factors after liquidation, but never resets dust_debt_raw. The stale
pre-liquidation dust value is subtracted from the freshly recalculated debt_raw
via get_net_debt_raw(), producing an understated old_net_debt_raw.

When update_total_borrow(new_net, old_net) runs, old_net is too small, so less
debt is removed from the aggregate than should be. The difference becomes phantom
debt that accumulates permanently with every liquidation.

Detection: In any lending protocol, look for:
- A position reconstruction function that recalculates debt/collateral from
  stored factors (fetch_latest_position pattern)
- A separate "dust" or "rounding remainder" field that is NOT reset inside the
  reconstruction function
- That dust field being used in a subtraction before being explicitly zeroed

Impact: Utilization rate = total_borrow / total_supply is permanently inflated.
Interest rates rise above correct level for all borrowers over time.

Real finding: Jupiter Lend, Code4rena Feb 2026. Disputed by sponsor (prady) —
sponsor claims liquidate() already removes dust via reduce_total_borrow().
Treat as contested — verify sponsor's argument before submitting similar findings.

Fix: Reset dust_debt_raw = 0 immediately after fetch_latest_position returns,
before get_net_debt_raw() is called.

### u128 Overflow in Liquidation Math Blocks Liquidation (Jupiter Lend S-1265)
get_debt_from_ratios uses safe_mul for u128 multiply-then-divide where the
intermediate product ref_ratio * debt overflows u128::MAX. The sibling function
get_col_from_ratios two lines below correctly uses safe_multiply_divide (U256)
and even has a developer comment warning about this risk.

Detection: In any protocol using tick-based or ratio-based liquidation math,
look for chained .safe_mul().safe_div() on values that could produce large
intermediates. Check if there's a U256 equivalent already imported.
Flag: safe_mul followed immediately by safe_div on variables named *ratio*,
*debt*, *ref_ratio* where either can be > 1e15.

Attack path: High price-ratio token pairs (protocol supports rates up to 1e24)
produce positions at high ticks. 10% oracle drop triggers liquidation loop.
ref_ratio (~6.15e21) * debt_internal (~8e16) = 4.92e38 > u128::MAX (3.4e38).
Liquidation permanently reverts. Bad debt accumulates.

Real finding: Jupiter Lend S-1265, Code4rena Feb 2026. Confirmed High.
Fix: Replace safe_mul().safe_div() with safe_multiply_divide() which uses U256.

### Interest Mode Switch Breaks Unit Invariants (Jupiter Lend S-1010)
Admin can switch a protocol position from with_interest (raw-share accounting)
to interest_free (nominal-amount accounting). Downstream modules unconditionally
treat get_amount() as raw and multiply by exchange price again, causing
double-conversion and value extraction.

Detection: Look for a mode flag (with_interest, interest_free, mode == 0/1)
on a position struct where the same get_amount() field is multiplied by an
exchange price in deposit/redeem paths WITHOUT first checking the mode flag.

Attack path after admin mode switch:
deposit(100) → Liquidity delta is already nominal (+100) → Lending multiplies
by exchange_price again → registered_amount = 150 → over-mints shares →
attacker redeems inflated shares → drains existing suppliers.

Real finding: Jupiter Lend S-1010, Code4rena Feb 2026. Confirmed Medium.
Sponsor disputed (never intended to switch mode in production).
Note: Admin-trust-dependent. Only flag if mode switching is possible AND
downstream math doesn't guard on mode.

## State Machine & Ordering Bugs

### Off-by-One in Branch Merge Comparison (Jupiter Lend S-979)
get_next_ref_tick() uses strict > instead of >= to determine if the current
tick is the branch's minima. When minima_tick == next_tick, the function
returns PERFECT (status 1) instead of LIQUIDATED (status 2), skipping the
base-branch merge. The merge executes one step late in a null iteration,
inflating B2's connection factor via an extra update_branch_debt_factor() call.
Result: attacker who borrows at exactly the branch's minima tick can repay
~0.44% less debt than borrowed.

Detection: In any liquidation loop with branch/range merge logic, look for
strict > comparisons between tick positions where equality should also trigger
the merge path. Pattern: if a > b && a > c vs correct if a >= b && a > c.

Attack path: requires 4 specific steps (partial liq → new borrow → attacker
borrow at exact tick → second liq) but all steps use normal user operations.
Attacker profit scales with borrow size. Repeatable across liquidation cycles.

Real finding: Jupiter Lend S-979, Code4rena Feb 2026. Confirmed Medium by judge.
Sponsor (prady) disputed — argued PERFECT before LIQUIDATED is correct two-phase
behavior. Treat as contested — verify the specific protocol's branch merge
ordering before submitting similar findings.

### Cumulative Rounding Desync Permanently Locks Positions (Jupiter Lend S-42)
Every partial payback applies two separate safe_sub(1) adjustments that compound:
1. position.rs subtracts 1 from payback_raw (vault keeps 1 extra unit of debt)
2. module/user.rs subtracts 1 more (Liquidity receives 1 extra token)

After N partial paybacks: vault debt_raw inflated by ~N units, Liquidity borrow
position is N tokens smaller. Max payback then derives amount from inflated
debt_raw, exceeds Liquidity's actual balance, hits safe_sub underflow → permanent
lockout. No admin rescue function exists.

Compounded by: operate() only checks position ownership for withdrawals and
borrows — NOT for paybacks. Any user can trigger the desync on any victim's
position by calling operate with negative debt_amount using their own tokens.

Detection:
- Look for multiple rounding adjustments (safe_sub(1), checked_sub(1)) on the
  same value across different layers during payback/repay flow
- Look for missing ownership check on repay: if auth is only checked for
  borrow/withdraw but not repay, third-party griefing is possible
- Pattern: if new_col < 0 || new_debt > 0 { verify_authority } → payback
  (new_debt < 0) skips check entirely

Attack path: Attacker calls operate 30 times with small payback amounts on
victim's position. Cost is ~$900 in payback tokens (not burned — reduces
victim's debt). Victim's position worth millions is permanently locked.
Victim cannot close via max payback (underflow) or partial payback (min_debt
check). Collateral permanently locked.

Real finding: Jupiter Lend S-42, Code4rena Feb 2026. Confirmed High.
Fix (two parts):
1. Cap max payback at Liquidity's actual borrow balance, not vault's debt_raw
2. Require position ownership for paybacks: if new_col < 0 || new_debt != 0
