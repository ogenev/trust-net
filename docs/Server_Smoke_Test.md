# Server-Mode Smoke Test (Local, No Chain, True 2-Hop)

This guide validates a real 2-hop decision path in server mode:

1. ingest `D -> E` and `E -> T` signed ratings (`POST /v1/ratings`)
2. build and insert a root epoch (`trustnet-root`)
3. fetch decision bundle for `(D, T)` (`GET /v1/decision`)
4. verify cryptographically (`trustnet-verify verify`)

## 1. Initialize a clean server-mode DB

Use a fresh DB file to avoid chain/server deployment mode conflicts.

```bash
DB_URL=sqlite://trustnet-smoke.db

cargo run -p trustnet-indexer --bin trustnet-indexer -- init-db --database-url "$DB_URL"
```

## 2. Start API (Terminal A)

```bash
DATABASE_URL="$DB_URL" \
TRUSTNET_API_WRITE_ENABLED=1 \
cargo run -p trustnet-api
```

Expected log line:

```text
TrustNet API server listening on 0.0.0.0:8080
```

## 3. Build two signed ratings (Terminal B)

Use separate keys for decider (`D`) and endorser (`E`), then create both edges:

- `E -> T` (to discover `E` principal id)
- `D -> E`

```bash
PK_D=0x1111111111111111111111111111111111111111111111111111111111111111
PK_E=0x2222222222222222222222222222222222222222222222222222222222222222
TARGET=0x3333333333333333333333333333333333333333
CONTEXT=trustnet:ctx:payments:v1

PAYLOAD_ET=$(cargo run -q -p trustnet-verifier --bin trustnet-rate -- \
  --private-key "$PK_E" \
  --target "$TARGET" \
  --context "$CONTEXT" \
  --level 2 \
  --compact)

ENDORSER=$(echo "$PAYLOAD_ET" | sed -E 's/.*"rater":"([^"]+)".*/\1/')
CTX=$(echo "$PAYLOAD_ET" | sed -E 's/.*"contextId":"([^"]+)".*/\1/')

PAYLOAD_DE=$(cargo run -q -p trustnet-verifier --bin trustnet-rate -- \
  --private-key "$PK_D" \
  --target "$ENDORSER" \
  --context "$CONTEXT" \
  --level 2 \
  --compact)

DECIDER=$(echo "$PAYLOAD_DE" | sed -E 's/.*"rater":"([^"]+)".*/\1/')

echo "DECIDER=$DECIDER"
echo "ENDORSER=$ENDORSER"
echo "TARGET=$TARGET"
echo "CTX=$CTX"
```

## 4. Post both ratings

```bash
curl -sS -X POST http://localhost:8080/v1/ratings \
  -H "content-type: application/json" \
  -d "$PAYLOAD_DE"

curl -sS -X POST http://localhost:8080/v1/ratings \
  -H "content-type: application/json" \
  -d "$PAYLOAD_ET"
```

Expected response shape:

```json
{"ok":true,"serverSeq":1}
{"ok":true,"serverSeq":2}
```

## 5. Build and insert a root epoch

```bash
cargo run -p trustnet-indexer --bin trustnet-root -- \
  --database-url "$DB_URL" \
  --publisher-key "$PK_D"
```

Expected output shape:

```text
Inserted epoch 1 (root=0x...)
```

## 6. Fetch root and decision bundles

```bash
curl -sS http://localhost:8080/v1/root > /tmp/root.json

curl -sS "http://localhost:8080/v1/decision?decider=$DECIDER&target=$TARGET&contextId=$CTX" \
  > /tmp/decision.json
```

In a successful 2-hop run, `/tmp/decision.json` should include:

- non-null `endorser` (equal to `$ENDORSER`)
- non-null `proofs.de` and `proofs.et`
- `decision: "allow"` (with default thresholds and both levels at `+2`)

## 7. Verify decision against root

```bash
cargo run -q -p trustnet-verifier --bin trustnet-verify -- \
  verify --root /tmp/root.json --bundle /tmp/decision.json
```

Expected output:

```text
OK
```

## Troubleshooting

- Error: `no such table: deployment_mode`
  - Run `cargo run -p trustnet-indexer --bin trustnet-indexer -- init-db --database-url "$DB_URL"` for the same `DATABASE_URL` used by the API.

- Error: `deployment_mode mismatch: expected 'server', got 'chain'`
  - Use a fresh DB file for server-mode smoke tests.

- `GET /v1/decision` returns `No epochs published`
  - Run `trustnet-root` after posting ratings.

- `endorser` is `null` or decision is not 2-hop
  - Confirm you posted both edges: positive `D -> E` and positive `E -> T`.
  - Confirm both edges use the same `contextId` and same DB file.
  - Confirm decision query is exactly `decider=$DECIDER&target=$TARGET`.
