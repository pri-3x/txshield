const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TX_HASH = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** Classifies the header search input; null when it is none of the known shapes. */
export function searchTarget(q: string, defaultChain: number): string | null {
  const v = q.trim();
  if (UUID.test(v)) return `/analyses/${v.toLowerCase()}`;
  if (TX_HASH.test(v)) return `/scan?hash=${v}&chainId=${defaultChain}`;
  if (ADDRESS.test(v)) return `/address?address=${v}&chainId=${defaultChain}`;
  return null;
}
