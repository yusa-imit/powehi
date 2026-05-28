/**
 * Integration tests for the Worker entry point (index.ts).
 *
 * Security invariants validated here:
 *   RED-1: PIPA guard reads request.cf.country, not the CF-IPCountry header.
 *          A spoofed CF-IPCountry header must NOT bypass the KR block.
 *   RED-2: Inbound IP/geo trust headers (X-Forwarded-For, X-Real-IP, CF-IPCountry,
 *          X-Real-IP, etc.) are stripped before forwarding to origin.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import worker from "./index";

// ── helpers ──────────────────────────────────────────────────────────────────

const EU = "https://eu.api.powehi.app";
const AP = "https://ap.api.powehi.app";

function makeKV(entries: Record<string, string> = {}): KVNamespace {
  return {
    get: async (key: string) => entries[key] ?? null,
    put: async () => {},
    delete: async () => {},
    list: async () => ({ keys: [], list_complete: true, cursor: "" }),
    getWithMetadata: async () => ({ value: null, metadata: null }),
  } as unknown as KVNamespace;
}

function makeEnv(kv: KVNamespace = makeKV()): { EU_ORIGIN: string; AP_ORIGIN: string; HEALTH_KV: KVNamespace } {
  return { EU_ORIGIN: EU, AP_ORIGIN: AP, HEALTH_KV: kv };
}

/** Build a Request with optional `cf` properties and extra headers. */
function makeRequest(
  path = "/v1/messages",
  cfCountry?: string,
  extraHeaders: Record<string, string> = {},
): Request {
  const req = new Request(`https://api.powehi.app${path}`, {
    headers: extraHeaders,
  });
  // Simulate the Cloudflare runtime injecting cf properties
  Object.defineProperty(req, "cf", {
    value: cfCountry !== undefined ? { country: cfCountry } : undefined,
    writable: false,
  });
  return req;
}

// ── RED-1: PIPA guard must read request.cf.country, not the header ────────

describe("RED-1: PIPA guard via request.cf.country", () => {
  it("blocks KR when cf.country=KR, even if CF-IPCountry header says DE", async () => {
    const req = makeRequest("/v1/test", "KR", { "CF-IPCountry": "DE" });
    const res = await worker.fetch(req, makeEnv());
    expect(res.status).toBe(503);
    const body = await res.json() as { code: string };
    expect(body.code).toBe("PIPA_REGION_PENDING");
  });

  it("routes DE when cf.country=DE (not blocked by spoofed KR header)", async () => {
    let capturedUrl = "";
    vi.stubGlobal("fetch", async (req: Request) => {
      capturedUrl = req.url;
      return new Response("ok", { status: 200 });
    });

    const req = makeRequest("/v1/test", "DE", { "CF-IPCountry": "KR" });
    const res = await worker.fetch(req, makeEnv());
    expect(res.status).toBe(200);
    expect(capturedUrl).toContain(EU);

    vi.unstubAllGlobals();
  });

  it("defaults to EU (XX) when cf is missing", async () => {
    let capturedUrl = "";
    vi.stubGlobal("fetch", async (req: Request) => {
      capturedUrl = req.url;
      return new Response("ok", { status: 200 });
    });

    // No cf properties on request
    const req = new Request("https://api.powehi.app/v1/test");
    const res = await worker.fetch(req, makeEnv());
    expect(res.status).toBe(200);
    expect(capturedUrl).toContain(EU);

    vi.unstubAllGlobals();
  });
});

// ── RED-2: Trust header stripping ─────────────────────────────────────────

describe("RED-2: Trust headers stripped before forwarding to origin", () => {
  const TRUST_HEADERS = [
    "x-forwarded-for",
    "x-real-ip",
    "cf-ipcountry",
    "cf-connecting-ip",
    "cf-visitor",
    "cf-ray",
    "forwarded",
  ] as const;

  beforeEach(() => {
    vi.stubGlobal("fetch", async (req: Request) => {
      return new Response(JSON.stringify({ forwarded_headers: Object.fromEntries(req.headers) }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
  });

  it("strips all IP/geo trust headers from the forwarded request", async () => {
    const spoofed: Record<string, string> = {
      "X-Forwarded-For": "10.0.0.1, 192.168.1.1",
      "X-Real-IP": "10.0.0.1",
      "CF-IPCountry": "DE",
      "CF-Connecting-IP": "1.2.3.4",
      "CF-Visitor": '{"scheme":"https"}',
      "CF-Ray": "abc123-FRA",
      "Forwarded": "for=1.2.3.4",
    };
    const req = makeRequest("/v1/messages", "DE", spoofed);
    let capturedReq!: Request;
    vi.stubGlobal("fetch", async (r: Request) => {
      capturedReq = r;
      return new Response("ok", { status: 200 });
    });

    await worker.fetch(req, makeEnv());

    for (const h of TRUST_HEADERS) {
      expect(capturedReq.headers.get(h)).toBeNull();
    }
  });

  it("sets X-Powehi-Region on forwarded request", async () => {
    let capturedReq!: Request;
    vi.stubGlobal("fetch", async (r: Request) => {
      capturedReq = r;
      return new Response("ok", { status: 200 });
    });

    const req = makeRequest("/v1/messages", "JP"); // JP → AP
    await worker.fetch(req, makeEnv());
    expect(capturedReq.headers.get("X-Powehi-Region")).toBe("ap");

    vi.unstubAllGlobals();
  });

  it("does not forward a stale X-Powehi-Region from the client", async () => {
    let capturedReq!: Request;
    vi.stubGlobal("fetch", async (r: Request) => {
      capturedReq = r;
      return new Response("ok", { status: 200 });
    });

    const req = makeRequest("/v1/messages", "DE", { "X-Powehi-Region": "ap" }); // DE→EU but client claims ap
    await worker.fetch(req, makeEnv());
    // Worker must overwrite with the real routing decision
    expect(capturedReq.headers.get("X-Powehi-Region")).toBe("eu");

    vi.unstubAllGlobals();
  });
});

// ── Origin failover behaviour ─────────────────────────────────────────────

describe("origin failover", () => {
  it("returns 503 ALL_REGIONS_DOWN when both origins are unhealthy", async () => {
    const kv = makeKV({ "health:eu": "unhealthy", "health:ap": "unhealthy" });
    const req = makeRequest("/v1/test", "DE");
    const res = await worker.fetch(req, makeEnv(kv));
    expect(res.status).toBe(503);
    const body = await res.json() as { code: string };
    expect(body.code).toBe("ALL_REGIONS_DOWN");
  });

  it("returns 503 ORIGIN_UNREACHABLE when fetch throws", async () => {
    vi.stubGlobal("fetch", async () => { throw new Error("network error"); });
    const req = makeRequest("/v1/test", "DE");
    const res = await worker.fetch(req, makeEnv());
    expect(res.status).toBe(503);
    const body = await res.json() as { code: string };
    expect(body.code).toBe("ORIGIN_UNREACHABLE");
    vi.unstubAllGlobals();
  });
});
