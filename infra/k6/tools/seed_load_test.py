#!/usr/bin/env python3
"""Seed N test devices + Redis sessions for Powehi k6 load testing.

Requirements:
    pip install psycopg2-binary redis

What this creates (in a NON-PRODUCTION environment only):
  - N rows in `users`  (handle_hash = raw ASCII b"k6-test-{i}", no OPAQUE record)
  - N rows in `devices` (dummy 32-byte mls_credential)
  - N Redis keys: SETEX session:<token-uuid> 86400 <device-uuid-bytes>
Existing rows with the same k6 prefix are deleted first so re-runs are safe.

Output:
  JSON array of session-token UUID strings → K6_TOKENS_FILE (default: /tmp/k6_tokens.json)
  Pass this file to ws_load_test.js via K6_TOKENS_FILE.

Usage:
    export DATABASE_URL="postgres://user:pass@localhost:5432/powehi"
    export REDIS_URL="redis://localhost:6379"
    python3 infra/k6/tools/seed_load_test.py --count 10000

WARNING: never run against production. Inserts dummy rows that bypass OPAQUE.
         The script refuses to run unless --allow-non-prod is passed.
"""

import argparse
import json
import os
import re
import sys
import uuid

try:
    import psycopg2          # psycopg2-binary
    import psycopg2.extras
    import redis as redis_lib
except ImportError:
    print("pip install psycopg2-binary redis", file=sys.stderr)
    sys.exit(1)

# Hostnames that must never appear in a load-test DB URL.
_PROD_HOSTNAME_PATTERNS = re.compile(
    r"(?:prod|production|live|release|main\.)",
    re.IGNORECASE,
)


def _refuse_production(db_url: str) -> None:
    if _PROD_HOSTNAME_PATTERNS.search(db_url):
        print(
            "ERROR: DATABASE_URL looks like a production connection string. "
            "Refusing to run. Pass --allow-non-prod only against a test DB.",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--count", type=int, default=100,
                        help="Number of sessions to create (default: 100)")
    parser.add_argument("--output", default="/tmp/k6_tokens.json",
                        help="Output JSON file (default: /tmp/k6_tokens.json)")
    parser.add_argument("--db-url",
                        default=os.environ.get("DATABASE_URL"),
                        help="Postgres DSN (or set DATABASE_URL)")
    parser.add_argument("--redis-url",
                        default=os.environ.get("REDIS_URL", "redis://localhost:6379"),
                        help="Redis URL (default: redis://localhost:6379)")
    parser.add_argument("--allow-non-prod", action="store_true",
                        help="Confirm you are targeting a NON-PRODUCTION database")
    args = parser.parse_args()

    if not args.db_url:
        print("ERROR: --db-url or DATABASE_URL required", file=sys.stderr)
        sys.exit(1)

    if not args.allow_non_prod:
        print(
            "ERROR: pass --allow-non-prod to confirm this is a non-production environment.",
            file=sys.stderr,
        )
        sys.exit(1)

    _refuse_production(args.db_url)

    print("Connecting to Postgres …", file=sys.stderr)
    try:
        conn = psycopg2.connect(args.db_url)
    except psycopg2.OperationalError:
        print("ERROR: could not connect to Postgres (check DATABASE_URL)", file=sys.stderr)
        sys.exit(1)

    print("Connecting to Redis …", file=sys.stderr)
    try:
        r = redis_lib.from_url(args.redis_url)
        r.ping()  # fail fast if Redis is unreachable
    except Exception:
        print("ERROR: could not connect to Redis (check REDIS_URL)", file=sys.stderr)
        sys.exit(1)

    tokens: list[str] = []

    with conn:
        with conn.cursor() as cur:
            # Remove previous k6 test rows so re-runs stay clean.
            # handle_hash is stored as raw ASCII bytes (b"k6-test-{i}"), not a real
            # OPAQUE hash; the LIKE pattern below identifies these sentinel rows.
            cur.execute(
                """
                DELETE FROM users
                WHERE handle_hash IN (
                    SELECT handle_hash FROM users
                    WHERE encode(handle_hash, 'escape') LIKE 'k6-test-%'
                )
                """,
            )
            deleted = cur.rowcount
            if deleted:
                print(f"Removed {deleted} stale k6 test users.", file=sys.stderr)

            # Batch insert: build lists for executemany.
            user_rows:   list[tuple] = []
            device_rows: list[tuple] = []
            session_map: list[tuple[str, bytes, str]] = []  # (token, device_bytes, device_id_str)

            for i in range(args.count):
                user_id   = uuid.uuid4()
                device_id = uuid.uuid4()
                token     = str(uuid.uuid4())

                # handle_hash: store raw ASCII bytes so the DELETE above can find them.
                # Real OPAQUE handle_hash = SHA-256(handle), but for load testing
                # we store a unique ASCII sentinel that the DELETE query can match.
                handle_hash = f"k6-test-{i}".encode()

                user_rows.append((str(user_id), handle_hash, ))
                device_rows.append((str(device_id), str(user_id), bytes(32)))
                session_map.append((token, device_id.bytes, str(device_id)))
                tokens.append(token)

            psycopg2.extras.execute_batch(
                cur,
                "INSERT INTO users (id, handle_hash, created_at, updated_at) "
                "VALUES (%s, %s, now(), now())",
                user_rows,
                page_size=500,
            )
            psycopg2.extras.execute_batch(
                cur,
                "INSERT INTO devices (id, user_id, mls_credential, created_at) "
                "VALUES (%s, %s, %s, now())",
                device_rows,
                page_size=500,
            )

    print(f"Inserted {args.count} users + devices.", file=sys.stderr)

    # Seed Redis sessions in pipeline batches of 500.
    SESSION_TTL = 86_400  # 24 h — matches auth_service::SESSION_TTL
    pipe = r.pipeline(transaction=False)
    for idx, (token, device_bytes, _) in enumerate(session_map):
        pipe.setex(f"session:{token}", SESSION_TTL, device_bytes)
        if (idx + 1) % 500 == 0:
            pipe.execute()
            pipe = r.pipeline(transaction=False)
            print(f"  Redis: {idx + 1}/{args.count} …", file=sys.stderr)
    pipe.execute()

    print(f"Seeded {args.count} Redis sessions.", file=sys.stderr)

    # Write with 0600 permissions: tokens are valid 24 h session credentials.
    old_umask = os.umask(0o177)
    try:
        with open(args.output, "w") as fh:
            json.dump(tokens, fh, indent=2)
    finally:
        os.umask(old_umask)

    print(f"Tokens written to {args.output}", file=sys.stderr)
    print(f"Run:  K6_TOKENS_FILE={args.output} k6 run infra/k6/ws_load_test.js",
          file=sys.stderr)


if __name__ == "__main__":
    main()
