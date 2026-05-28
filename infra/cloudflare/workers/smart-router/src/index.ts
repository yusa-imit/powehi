/**
 * Powehi smart-router Cloudflare Worker
 *
 * Routes API traffic to the nearest healthy region (EU or AP-Singapore).
 * Zero-knowledge: this Worker NEVER reads or logs request/response bodies.
 * Data residency: Korean users (KR) receive 503 until PIPA-compliant Korean DC is live.
 *
 * Health state is read from HEALTH_KV (written by synthetic monitors every 10 min).
 * Keys: "health:eu" | "health:ap" — value "healthy" | "unhealthy".
 * Default assumption when key absent: healthy (fail-open for EU; AP guarded by AP_COUNTRIES set).
 */

import { pickOrigin, rewriteUrl, resolveTarget } from "./router";

export interface Env {
  /** https://eu.api.powehi.app (Hetzner nbg1) */
  EU_ORIGIN: string;
  /** https://ap.api.powehi.app (Hetzner sin1 — Singapore) */
  AP_ORIGIN: string;
  /** KV namespace storing health state written by k6 synthetic monitors */
  HEALTH_KV: KVNamespace;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const country = request.headers.get("CF-IPCountry") ?? "XX";
    const decision = resolveTarget(country);

    if (decision.kind === "pipa_blocked") {
      return pipaBlockedResponse();
    }

    const target = decision.target;

    // Read health state — treat missing key as healthy (fail-open)
    const [euState, apState] = await Promise.all([
      env.HEALTH_KV.get("health:eu"),
      env.HEALTH_KV.get("health:ap"),
    ]);
    const euHealthy = euState !== "unhealthy";
    const apHealthy = apState !== "unhealthy";

    const originBase = pickOrigin(
      target,
      env.EU_ORIGIN,
      env.AP_ORIGIN,
      euHealthy,
      apHealthy,
    );

    if (originBase === null) {
      return new Response(
        JSON.stringify({ error: "service_unavailable", code: "ALL_REGIONS_DOWN" }),
        { status: 503, headers: { "Content-Type": "application/json" } },
      );
    }

    const targetUrl = rewriteUrl(request.url, originBase);

    // Forward headers — strip CF-Connecting-IP before sending to origin
    const forwardHeaders = new Headers(request.headers);
    forwardHeaders.delete("CF-Connecting-IP");
    // Indicate which region was selected so origin can log it (opaque label, no PII)
    forwardHeaders.set("X-Powehi-Region", target);

    const forwardedRequest = new Request(targetUrl, {
      method: request.method,
      headers: forwardHeaders,
      body: request.body,
      // Workers do not support duplex: "half" directly; body streaming is implicit
      redirect: "manual",
    });

    return fetch(forwardedRequest);
  },
};

function pipaBlockedResponse(): Response {
  return new Response(
    JSON.stringify({
      error: "service_unavailable",
      code: "PIPA_REGION_PENDING",
      // No user-identifying info in this response
    }),
    {
      status: 503,
      headers: {
        "Content-Type": "application/json",
        "Retry-After": "86400",
      },
    },
  );
}
