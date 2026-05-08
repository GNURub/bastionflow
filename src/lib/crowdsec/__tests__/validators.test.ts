import { describe, expect, it } from "vitest";
import { createDecisionSchema } from "../validators";

describe("createDecisionSchema", () => {
  it("accepts safe manual IPv4 decisions", () => {
    expect(createDecisionSchema.safeParse({ scope: "ip", value: "203.0.113.4", type: "ban", duration: "30m", reason: "probe burst", mode: "manual" }).success).toBe(true);
  });

  it("rejects malformed IP values", () => {
    expect(createDecisionSchema.safeParse({ scope: "ip", value: "not-an-ip", type: "ban", duration: "30m", reason: "probe burst", mode: "manual" }).success).toBe(false);
  });
});
