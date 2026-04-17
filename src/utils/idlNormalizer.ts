export function normalizeIDL(idl: any): any {
  // Already v1 format
  if (idl.name && idl.instructions?.[0]?.accounts?.[0]?.isMut !== undefined) {
    return idl;
  }

  // V2 format — normalize to v1
  return {
    name: idl.metadata?.name ?? idl.name ?? 'unknown',
    version: idl.metadata?.version ?? idl.version,
    instructions: (idl.instructions ?? []).map((ix: any) => ({
      ...ix,
      accounts: (ix.accounts ?? []).map((acc: any) => ({
        ...acc,
        isMut: acc.writable ?? acc.isMut ?? false,
        isSigner: acc.signer ?? acc.isSigner ?? false,
      })),
    })),
    accounts: idl.accounts ?? [],
    types: idl.types ?? [],
  };
}