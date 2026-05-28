import { describe, it, expect } from "vitest";
import {
  resolveTarget,
  pickOrigin,
  rewriteUrl,
  PIPA_BLOCKED_COUNTRIES,
  AP_COUNTRIES,
} from "./router";

describe("resolveTarget", () => {
  it("blocks KR users (PIPA guard)", () => {
    expect(resolveTarget("KR")).toEqual({ kind: "pipa_blocked" });
    expect(resolveTarget("kr")).toEqual({ kind: "pipa_blocked" });
  });

  it("routes AP countries to ap region", () => {
    for (const country of ["JP", "SG", "TW", "AU", "IN"]) {
      expect(resolveTarget(country)).toEqual({ kind: "route", target: "ap" });
    }
  });

  it("routes EU/other countries to eu region", () => {
    for (const country of ["DE", "FR", "US", "GB", "BR", "XX"]) {
      expect(resolveTarget(country)).toEqual({ kind: "route", target: "eu" });
    }
  });

  it("normalises lower-case input", () => {
    expect(resolveTarget("jp")).toEqual({ kind: "route", target: "ap" });
    expect(resolveTarget("de")).toEqual({ kind: "route", target: "eu" });
  });

  it("treats unknown country code as EU (default)", () => {
    expect(resolveTarget("ZZ")).toEqual({ kind: "route", target: "eu" });
  });
});

describe("pickOrigin", () => {
  const EU = "https://eu.api.powehi.app";
  const AP = "https://ap.api.powehi.app";

  it("returns AP origin when both healthy and target is ap", () => {
    expect(pickOrigin("ap", EU, AP, true, true)).toBe(AP);
  });

  it("returns EU origin when both healthy and target is eu", () => {
    expect(pickOrigin("eu", EU, AP, true, true)).toBe(EU);
  });

  it("fails over AP→EU when AP is unhealthy", () => {
    expect(pickOrigin("ap", EU, AP, true, false)).toBe(EU);
  });

  it("fails over EU→AP when EU is unhealthy", () => {
    expect(pickOrigin("eu", EU, AP, false, true)).toBe(AP);
  });

  it("returns null when both regions are unhealthy", () => {
    expect(pickOrigin("eu", EU, AP, false, false)).toBeNull();
    expect(pickOrigin("ap", EU, AP, false, false)).toBeNull();
  });
});

describe("rewriteUrl", () => {
  it("replaces host and protocol while preserving path and query", () => {
    const result = rewriteUrl(
      "https://api.powehi.app/v1/messages?since=123",
      "https://eu.api.powehi.app",
    );
    expect(result).toBe("https://eu.api.powehi.app/v1/messages?since=123");
  });

  it("handles root path", () => {
    const result = rewriteUrl("https://api.powehi.app/", "https://ap.api.powehi.app");
    expect(result).toBe("https://ap.api.powehi.app/");
  });
});

describe("PIPA_BLOCKED_COUNTRIES", () => {
  it("contains exactly KR", () => {
    expect(PIPA_BLOCKED_COUNTRIES.has("KR")).toBe(true);
    expect(PIPA_BLOCKED_COUNTRIES.size).toBe(1);
  });
});

describe("AP_COUNTRIES", () => {
  it("does not contain KR (PIPA guard)", () => {
    expect(AP_COUNTRIES.has("KR")).toBe(false);
  });

  it("contains expected AP countries", () => {
    for (const c of ["JP", "SG", "AU", "IN", "TW"]) {
      expect(AP_COUNTRIES.has(c)).toBe(true);
    }
  });

  it("does not contain EU countries", () => {
    for (const c of ["DE", "FR", "GB", "PL", "US"]) {
      expect(AP_COUNTRIES.has(c)).toBe(false);
    }
  });
});
