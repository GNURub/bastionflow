import { describe, expect, it } from "vitest";
import { isAllowedTarget } from "../ip-allowlist";

describe("isAllowedTarget", () => {
  it("matches exact IPs", () => {
    expect(isAllowedTarget("127.0.0.1", ["127.0.0.1"])).toBe(true);
  });

  it("matches IPv4 CIDR entries", () => {
    expect(isAllowedTarget("192.168.1.42", ["192.168.0.0/16"])).toBe(true);
    expect(isAllowedTarget("198.51.100.10", ["192.168.0.0/16"])).toBe(false);
  });
});
