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

### Stale dust_debt_raw (Jupiter Lend)
fetch_latest_position recalculates debt_raw and col_raw from branch factors
but never resets dust_debt_raw. Stale pre-liquidation dust fed into
get_net_debt_raw() understates old_net_debt_raw, causing phantom debt
accumulation in total_borrow after each liquidation.

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
