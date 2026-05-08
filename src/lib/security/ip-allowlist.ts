function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!) >>> 0;
}

function matchesCidr(ip: string, cidr: string): boolean {
  const [network, prefixRaw] = cidr.split("/");
  const prefix = Number(prefixRaw);
  const ipInt = ipv4ToInt(ip);
  const networkInt = network ? ipv4ToInt(network) : null;
  if (ipInt === null || networkInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (networkInt & mask);
}

export function isAllowedTarget(value: string, allowlist: readonly string[]): boolean {
  const normalized = value.trim().toLowerCase();
  return allowlist.some((entry) => {
    const candidate = entry.trim().toLowerCase();
    if (!candidate) return false;
    if (candidate === normalized) return true;
    if (candidate.includes("/") && !normalized.includes("/")) return matchesCidr(normalized, candidate);
    return false;
  });
}
