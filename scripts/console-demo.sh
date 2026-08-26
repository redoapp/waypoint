#!/usr/bin/env bash
# Bring up a throwaway seeded Postgres + Redis and run the web console
# against them. Nothing here touches the production backend that
# waypoint-dev.toml points at.
#
#   console-demo                 start containers, seed, run the console
#   console-demo --stop          tear the containers down
#   console-demo --seed          re-seed only (containers keep running)
#
# Extra flags are passed through to the demo binary, e.g.:
#   console-demo -preset readonly       see the permission warnings
#   console-demo -v                     verbose waypoint logs
#
# No Tailscale auth key is needed: the demo runs an in-process mock control
# plane. See website docs for running the console on a real tailnet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PG_CONTAINER="waypoint-console-pg"
REDIS_CONTAINER="waypoint-console-redis"
PG_PORT="${CONSOLE_DEMO_PG_PORT:-55432}"
REDIS_PORT="${CONSOLE_DEMO_REDIS_PORT:-56379}"
LISTEN_PORT="${CONSOLE_DEMO_PORT:-8080}"

if command -v podman >/dev/null 2>&1; then
  RUNTIME=podman
elif command -v docker >/dev/null 2>&1; then
  RUNTIME=docker
else
  echo "error: neither podman nor docker is available" >&2
  exit 1
fi

stop() {
  echo "stopping demo containers…"
  $RUNTIME rm -f "$PG_CONTAINER" "$REDIS_CONTAINER" >/dev/null 2>&1 || true
  echo "done. (state dir .waypoint/console-demo-state left in place)"
}

if [ "${1:-}" = "--stop" ]; then
  stop
  exit 0
fi

start_containers() {
  if ! $RUNTIME container exists "$PG_CONTAINER" 2>/dev/null && \
     ! $RUNTIME inspect "$PG_CONTAINER" >/dev/null 2>&1; then
    echo "starting postgres on :$PG_PORT…"
    $RUNTIME run -d --name "$PG_CONTAINER" \
      -e POSTGRES_PASSWORD=demopw \
      -e POSTGRES_DB=appdb \
      -p "$PG_PORT:5432" \
      docker.io/library/postgres:17-alpine >/dev/null
  else
    $RUNTIME start "$PG_CONTAINER" >/dev/null 2>&1 || true
    echo "reusing postgres container on :$PG_PORT"
  fi

  if ! $RUNTIME inspect "$REDIS_CONTAINER" >/dev/null 2>&1; then
    echo "starting redis on :$REDIS_PORT…"
    $RUNTIME run -d --name "$REDIS_CONTAINER" \
      -p "$REDIS_PORT:6379" \
      docker.io/library/redis:7-alpine >/dev/null
  else
    $RUNTIME start "$REDIS_CONTAINER" >/dev/null 2>&1 || true
    echo "reusing redis container on :$REDIS_PORT"
  fi

  printf "waiting for postgres"
  for _ in $(seq 1 300); do
    if $RUNTIME exec "$PG_CONTAINER" psql -U postgres -d appdb -tAc "select 1" >/dev/null 2>&1; then
      echo " ready"
      return 0
    fi
    printf "."
  done
  echo
  echo "error: postgres did not become ready" >&2
  exit 1
}

seed() {
  echo "seeding appdb…"
  $RUNTIME exec -i "$PG_CONTAINER" psql -U postgres -d appdb -q <<'SQL'
DROP TABLE IF EXISTS item_returns, label_scans, labels, shipments, order_items, orders, customers, regions CASCADE;
DROP TYPE IF EXISTS order_status CASCADE;

CREATE TYPE order_status AS ENUM ('pending', 'paid', 'shipped', 'delivered', 'refunded');

CREATE TABLE regions (
    id          smallserial PRIMARY KEY,
    code        text NOT NULL UNIQUE,
    name        text NOT NULL
);
COMMENT ON TABLE regions IS 'Fulfilment regions. Small, stable lookup table.';

CREATE TABLE customers (
    id          bigserial PRIMARY KEY,
    email       text NOT NULL UNIQUE,
    name        text NOT NULL,
    region_id   smallint REFERENCES regions(id),
    created_at  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON COLUMN customers.email IS 'Primary contact address; unique per tenant.';
COMMENT ON COLUMN customers.region_id IS 'Fulfilment region. Null for legacy accounts.';

CREATE TABLE orders (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id),
    status      order_status NOT NULL DEFAULT 'pending',
    total       numeric(10,2) NOT NULL,
    placed_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON COLUMN orders.total IS 'Order total in the customer''s billing currency.';

CREATE TABLE order_items (
    order_id    bigint NOT NULL REFERENCES orders(id),
    sku         text NOT NULL,
    qty         int NOT NULL CHECK (qty > 0),
    unit_price  numeric(10,2) NOT NULL,
    PRIMARY KEY (order_id, sku)
);

-- A genuine two-column foreign key, so join completion has a composite key to
-- render: picking item_returns after JOIN emits both predicates, AND-ed.
CREATE TABLE item_returns (
    id          bigserial PRIMARY KEY,
    order_id    bigint NOT NULL,
    sku         text NOT NULL,
    reason      text,
    returned_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (order_id, sku) REFERENCES order_items(order_id, sku)
);
COMMENT ON TABLE item_returns IS 'Returns, keyed by the composite order_items key.';

CREATE TABLE shipments (
    id          bigserial PRIMARY KEY,
    order_id    bigint NOT NULL REFERENCES orders(id),
    carrier     text NOT NULL,
    shipped_at  timestamptz
);

-- labels reaches customers only through shipments → orders, which is what
-- makes multi-hop join completion worth trying.
CREATE TABLE labels (
    id          bigserial PRIMARY KEY,
    shipment_id bigint NOT NULL REFERENCES shipments(id),
    tracking    text NOT NULL UNIQUE
);

CREATE TABLE label_scans (
    id          bigserial PRIMARY KEY,
    label_id    bigint NOT NULL REFERENCES labels(id),
    scanned_at  timestamptz NOT NULL DEFAULT now(),
    location    text
);

INSERT INTO regions (code, name) VALUES
    ('us-east','US East'), ('us-west','US West'), ('eu','Europe'), ('apac','Asia Pacific');

INSERT INTO customers (email, name, region_id)
SELECT 'user' || g || '@example.com',
       (ARRAY['Ada','Grace','Alan','Edsger','Barbara','Ken','Donald','Margaret'])[1 + (g % 8)]
         || ' ' || (ARRAY['Lovelace','Hopper','Turing','Dijkstra','Liskov','Thompson','Knuth','Hamilton'])[1 + (g % 8)],
       1 + (g % 4)
FROM generate_series(1, 250) g;

INSERT INTO orders (customer_id, status, total, placed_at)
SELECT 1 + (g % 250),
       (ARRAY['pending','paid','shipped','delivered','refunded']::order_status[])[1 + (g % 5)],
       round((random() * 480 + 12)::numeric, 2),
       now() - (g || ' hours')::interval
FROM generate_series(1, 1200) g;

INSERT INTO order_items (order_id, sku, qty, unit_price)
SELECT o.id,
       'SKU-' || lpad(((o.id * 7 + s) % 400)::text, 4, '0'),
       1 + ((o.id + s) % 4),
       round((random() * 90 + 5)::numeric, 2)
FROM orders o
CROSS JOIN generate_series(1, 3) s
ON CONFLICT DO NOTHING;

INSERT INTO item_returns (order_id, sku, reason)
SELECT oi.order_id, oi.sku,
       (ARRAY['damaged','wrong size','not as described','changed mind'])[1 + (oi.order_id % 4)]
FROM order_items oi
WHERE oi.order_id % 17 = 0;

INSERT INTO shipments (order_id, carrier, shipped_at)
SELECT o.id,
       (ARRAY['ups','fedex','dhl','usps'])[1 + (o.id % 4)],
       o.placed_at + interval '2 days'
FROM orders o
WHERE o.status IN ('shipped','delivered');

INSERT INTO labels (shipment_id, tracking)
SELECT s.id, 'TRK' || lpad(s.id::text, 10, '0') FROM shipments s;

INSERT INTO label_scans (label_id, scanned_at, location)
SELECT l.id,
       now() - ((l.id % 72) || ' hours')::interval,
       (ARRAY['depot','in transit','out for delivery','delivered'])[1 + (l.id % 4)]
FROM labels l
CROSS JOIN generate_series(1, 2);

ANALYZE;
SQL

  # Real counts, not pg_stat_user_tables.n_live_tup, which is an estimate and
  # overcounts after a bulk load.
  # A second database, so the console's picker has more than one entry.
  $RUNTIME exec "$PG_CONTAINER" psql -U postgres -q -c "DROP DATABASE IF EXISTS analytics WITH (FORCE)" >/dev/null 2>&1 || true
  $RUNTIME exec "$PG_CONTAINER" psql -U postgres -q -c "CREATE DATABASE analytics" >/dev/null 2>&1 || true
  $RUNTIME exec -i "$PG_CONTAINER" psql -U postgres -d analytics -q <<'ASQL'
DROP TABLE IF EXISTS page_views, sessions CASCADE;
CREATE TABLE sessions (id bigserial PRIMARY KEY, visitor text, started_at timestamptz DEFAULT now());
CREATE TABLE page_views (
    id         bigserial PRIMARY KEY,
    session_id bigint NOT NULL REFERENCES sessions(id),
    path       text,
    viewed_at  timestamptz DEFAULT now()
);
INSERT INTO sessions (visitor) SELECT 'visitor-' || g FROM generate_series(1, 60) g;
INSERT INTO page_views (session_id, path)
SELECT 1 + (g % 60), (ARRAY['/','/pricing','/docs','/blog'])[1 + (g % 4)]
FROM generate_series(1, 400) g;
ASQL

  echo "seeded:"
  $RUNTIME exec -i "$PG_CONTAINER" psql -U postgres -d appdb -tAc "
    SELECT '  ' || t.relname || ': ' || c.n
    FROM (VALUES ('regions'),('customers'),('orders'),('order_items'),
                 ('item_returns'),('shipments'),('labels'),('label_scans')) AS t(relname)
    CROSS JOIN LATERAL (
      SELECT (xpath('/row/c/text()',
        query_to_xml('SELECT count(*) AS c FROM ' || quote_ident(t.relname),
                     false, true, '')))[1]::text::bigint AS n
    ) c
    ORDER BY t.relname"
}

if [ "${1:-}" = "--seed" ]; then
  seed
  exit 0
fi

start_containers
seed

PRESET="${CONSOLE_DEMO_PRESET:-readwrite}"

cat <<MSG

Starting the console against an in-process mock Tailscale control plane.
No auth key, no tailnet, and no ACL changes: the demo runs its own control
plane and joins it as a second node standing in for your browser, so requests
still reach the console from a real peer and are still authorized by a real
WhoIs against a real capability grant.

MSG

exec go run -tags demo ./cmd/waypoint-console-demo \
  -addr "127.0.0.1:$LISTEN_PORT" \
  -backend "127.0.0.1:$PG_PORT" \
  -admin-user postgres \
  -admin-password demopw \
  -database "appdb,analytics" \
  -redis "127.0.0.1:$REDIS_PORT" \
  -preset "$PRESET" \
  "$@"
