/**
 * Powehi smart-router — pure routing logic (no CF APIs; testable).
 *
 * Data-residency invariant (prd.md §4A.1):
 *   - KR country is PIPA-blocked until a real Korean DC is available.
 *   - AP_COUNTRIES route to sin1 (Singapore); all others go to EU (nbg1).
 *   - The router never reads request bodies — zero-knowledge by design.
 */

export const PIPA_BLOCKED_COUNTRIES: ReadonlySet<string> = new Set(["KR"]);

export const AP_COUNTRIES: ReadonlySet<string> = new Set([
  // East Asia (excluding KR — PIPA blocked)
  "JP", "TW", "HK", "MO", "CN",
  // Southeast Asia
  "SG", "PH", "MY", "ID", "TH", "VN", "MM", "KH", "LA", "BN", "TL",
  // South Asia
  "IN", "BD", "LK", "NP", "PK", "MV",
  // Pacific
  "AU", "NZ", "PG", "FJ", "WS", "TO",
]);

export type RegionTarget = "eu" | "ap";
export type RouteDecision =
  | { kind: "route"; target: RegionTarget }
  | { kind: "pipa_blocked" };

/**
 * Determine routing target from the CF-IPCountry header value.
 * Pure function — no I/O, fully testable.
 */
export function resolveTarget(countryCode: string): RouteDecision {
  const country = countryCode.toUpperCase();
  if (PIPA_BLOCKED_COUNTRIES.has(country)) {
    return { kind: "pipa_blocked" };
  }
  return { kind: "route", target: AP_COUNTRIES.has(country) ? "ap" : "eu" };
}

/**
 * Choose the actual origin URL, applying health-state failover.
 * Returns `null` if both origins are unhealthy (caller should 503).
 */
export function pickOrigin(
  target: RegionTarget,
  euOrigin: string,
  apOrigin: string,
  euHealthy: boolean,
  apHealthy: boolean,
): string | null {
  if (target === "ap") {
    if (apHealthy) return apOrigin;
    if (euHealthy) return euOrigin; // failover
    return null;
  }
  if (euHealthy) return euOrigin;
  if (apHealthy) return apOrigin; // failover
  return null;
}

/** Rewrite a request URL to point at the chosen origin, preserving path+query. */
export function rewriteUrl(originalUrl: string, originBase: string): string {
  const orig = new URL(originalUrl);
  const base = new URL(originBase);
  orig.protocol = base.protocol;
  orig.hostname = base.hostname;
  orig.port = base.port;
  return orig.toString();
}
