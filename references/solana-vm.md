# Solana VM Security Constraints — SolSentry Reference

## Stack Limits
- Max stack frame: 4096 bytes per function call frame
- InterfaceAccount<'info, TokenAccount> ≈ 200+ bytes on stack
- Box<> moves to heap — use for large fields in account structs
- Symptom: compiles successfully, instruction reverts at runtime
  with "stack offset exceeded" or "access violation"
- Detection: 5+ unboxed InterfaceAccount fields in one #[derive(Accounts)] struct

## Compute Budget
- Default: 200,000 compute units per transaction
- Max with requestComputeUnits: 1,400,000
- Unbounded loops over user-controlled data = compute DoS vector
- O(N) operations under global write locks are critical severity
  Real finding: Sei blockchain CalculateNextNonce — O(N) loop under write lock,
  regression from O(log N) binary search introduced in commit 30006a197

## Rent
- Accounts must maintain rent-exempt balance
- Anchor close constraint: safe 3-step close (zero data, transfer lamports, assign to system program)
- Manual close sequence if not using Anchor:
  1. Zero account data
  2. Transfer lamports to recipient  
  3. Assign ownership to System Program
- Never close to user-supplied arbitrary address — always trusted recipient

## Account Model
- All accounts declared upfront in instruction context
- remaining_accounts: dynamic accounts bypassing type safety
  — always validate owner, type, and key for each
- PDAs cannot sign external transactions — only via invoke_signed with seeds
- Canonical bump must be stored at init time and reused — never re-derive

## Transaction Atomicity
- All CPIs within one transaction are atomic
- Post-CPI: always reload account data before using (Anchor: .reload()?)
- Flash loans: borrow and repay must occur within same transaction
- Two-step patterns (prepare + execute) break atomicity — state consistency
  must be verified across both calls
