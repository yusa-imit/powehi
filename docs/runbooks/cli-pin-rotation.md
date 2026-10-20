# CLI certificate pin rotation

Mechanism: `crates/client/powehi-cli/src/pinning.rs` (Phase 8 item 8.7, prd §3.1 T2, §7A.3).
Every TLS connection of the CLI (REST and `/v1/ws`) first passes normal WebPKI verification
and then must present a chain in which at least one certificate's SPKI SHA-256 is in
`PRODUCTION_PINS`. A pin never replaces the CA check. A pinned intermediate counts only if verifying the
leaf with that certificate as the sole trust anchor succeeds, so extra certificates a server
appends prove nothing. Root keys cannot be pinned (servers do not send roots).

## What is pinned

The edge uses Cloudflare-managed certificates, so the leaf key rotates without our control.
Pin **issuing CA (intermediate) keys**, not the leaf: the pin set holds the intermediate(s)
Cloudflare currently issues from plus at least one backup (another intermediate of the same
or an alternate CA). The set must hold 2..=8 distinct pins; `PinSet::new` rejects anything
else. While `PRODUCTION_PINS` is empty (until Phase 9 task 9.9, ADR-0007) the CLI verifies
with WebPKI only.

## Computing a pin

```sh
openssl x509 -in cert.pem -noout -pubkey \
  | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | xxd -i
```

Check the value against `pinning::spki_pin` on the same certificate before shipping.

## Rotation (no flag day)

1. Add the new key's pin to `PRODUCTION_PINS` **before** the edge starts using it
   (the backup slot exists for this). Release the CLI.
2. Wait until the supported CLI versions carry the new pin (releases older than this
   have no way to learn it: they must update first).
3. Switch the edge to the new key. With Cloudflare-managed certificates this step is not in
   our hands (see the open pin-strategy issue); it works only with a custom certificate.
4. Retire the old pin in a later release; keep at least two pins in the set.

## Emergency

A CLI whose pins all mismatch fails closed (no connection) and prints "could not reach the
server". Recovery is a new CLI release with the corrected set; there is no runtime override
and no environment switch, by design (a switch an attacker can flip is no pin).
