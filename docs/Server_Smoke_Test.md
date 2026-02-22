# Server-Mode Smoke Test (Local, No Chain, True 2-Hop)

> v1.1 note: This guide validates server-mode score proof generation without chain anchoring.

This guide validates a real 2-hop score path in server mode:

1. ingest `D -> E` and `E -> T` signed ratings (`POST /v1/ratings`)
2. build and insert a root epoch (`trustnet root`)
3. fetch score bundle for `(D, T)` (`GET /v1/score/:decider/:target?contextTag=...`)
4. verify cryptographically (`trustnet verify`)

By default, this walkthrough uses `trustnet:ctx:code-exec:v1` to match the initial OpenClaw-focused MVP.

## Automated smoke test

Run the in-process integration test (same flow as this doc):

```bash
cargo test -p trustnet-api --test server_smoke
```

## 1. Initialize a clean server-mode DB

Use a fresh DB file to avoid chain/server deployment mode conflicts.

```bash
DB_URL=sqlite://trustnet-smoke.db

cargo run -p trustnet-indexer -- init-db --database-url "$DB_URL"
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
CONTEXT=trustnet:ctx:code-exec:v1

PAYLOAD_ET=$(cargo run -q -p trustnet-cli -- rate \
  --private-key "$PK_E" \
  --target "$TARGET" \
  --context "$CONTEXT" \
  --level 2 \
  --compact)

ENDORSER=$(echo "$PAYLOAD_ET" | sed -E 's/.*"rater":"([^"]+)".*/\1/')

PAYLOAD_DE=$(cargo run -q -p trustnet-cli -- rate \
  --private-key "$PK_D" \
  --target "$ENDORSER" \
  --context "$CONTEXT" \
  --level 2 \
  --compact)

DECIDER=$(echo "$PAYLOAD_DE" | sed -E 's/.*"rater":"([^"]+)".*/\1/')

echo "DECIDER=$DECIDER"
echo "ENDORSER=$ENDORSER"
echo "TARGET=$TARGET"
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
DB_URL=sqlite://trustnet-smoke.db

cargo run -p trustnet-cli -- root \
  --database-url "$DB_URL" \
  --publisher-key "$PK_D"
```

Expected output shape:

```text
Inserted epoch 1 (root=0x...)
```

## 6. Fetch root and score bundles

```bash
curl -sS http://localhost:8080/v1/root > /tmp/root.json

curl -sS "http://localhost:8080/v1/score/$DECIDER/$TARGET?contextTag=$CONTEXT" \
  > /tmp/score.json
```

In a successful 2-hop run, `/tmp/score.json` should include:

- non-null `proof.endorser` (equal to `$ENDORSER`)
- non-null `proof.proofs.DE` and `proof.proofs.ET`
- `score >= 1` (with both edges at `+2`, score is `+2`)

## 7. Verify score against root

```bash
cargo run -q -p trustnet-cli -- verify \
  --root /tmp/root.json --bundle /tmp/score.json
```

Expected output:

```text
OK
```

## Troubleshooting

- Error: `no such table: deployment_mode`
  - Run `cargo run -p trustnet-indexer -- init-db --database-url "$DB_URL"` for the same `DATABASE_URL` used by the API.

- Error: `deployment_mode mismatch: expected 'server', got 'chain'`
  - Use a fresh DB file for server-mode smoke tests.

- `GET /v1/score/...` returns `No epochs published`
  - Run `cargo run -p trustnet-cli -- root --database-url "$DB_URL" --publisher-key "$PK_D"` after posting ratings.

- `proof.endorser` is `null` or score is not 2-hop-derived
  - Confirm you posted both edges: positive `D -> E` and positive `E -> T`.
  - Confirm both edges use the same context and same DB file.
  - Confirm score query is exactly `/v1/score/$DECIDER/$TARGET?contextTag=$CONTEXT`.
