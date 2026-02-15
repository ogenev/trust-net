#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trustnet-chain-smoke.XXXXXX")"

ANVIL_PID=""
INDEXER_PID=""
API_PID=""

cleanup() {
  set +e

  if [[ -n "${API_PID}" ]]; then
    kill "${API_PID}" >/dev/null 2>&1 || true
    wait "${API_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${INDEXER_PID}" ]]; then
    kill "${INDEXER_PID}" >/dev/null 2>&1 || true
    wait "${INDEXER_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${ANVIL_PID}" ]]; then
    kill "${ANVIL_PID}" >/dev/null 2>&1 || true
    wait "${ANVIL_PID}" >/dev/null 2>&1 || true
  fi

  if [[ "${CHAIN_SMOKE_KEEP_TMP:-0}" == "1" ]]; then
    echo "keeping temp dir: ${TMP_DIR}"
  else
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

wait_for_rpc() {
  local attempts=0
  until cast block-number --rpc-url "${RPC_URL}" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if ((attempts > 30)); then
      echo "anvil RPC did not become ready in time" >&2
      exit 1
    fi
    sleep 1
  done
}

wait_for_http() {
  local url="$1"
  local attempts=0
  until curl -fsS "${url}" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if ((attempts > 60)); then
      echo "endpoint did not become ready in time: ${url}" >&2
      exit 1
    fi
    sleep 1
  done
}

wait_for_sql_count_at_least() {
  local db_file="$1"
  local table="$2"
  local min_count="$3"
  local attempts=0

  while true; do
    local count
    count="$(sqlite3 "${db_file}" "SELECT COUNT(*) FROM ${table};" | tr -d '[:space:]')"
    if [[ "${count}" =~ ^[0-9]+$ ]] && ((count >= min_count)); then
      return 0
    fi
    attempts=$((attempts + 1))
    if ((attempts > 90)); then
      echo "timed out waiting for ${table} count >= ${min_count} (last=${count})" >&2
      exit 1
    fi
    sleep 1
  done
}

deploy_contract() {
  local contract="$1"
  shift || true
  local constructor_sig="${1:-}"
  local deployment_data
  local bytecode

  if [[ -n "${constructor_sig}" ]]; then
    shift
  fi

  bytecode="$(forge inspect --via-ir "${contract}" bytecode)"
  if [[ "${bytecode}" == "0x" || -z "${bytecode}" ]]; then
    echo "failed to get bytecode for ${contract}" >&2
    exit 1
  fi

  if [[ -n "${constructor_sig}" ]]; then
    local encoded_ctor
    encoded_ctor="$(cast abi-encode "${constructor_sig}" "$@")"
    deployment_data="${bytecode}${encoded_ctor#0x}"
  else
    deployment_data="${bytecode}"
  fi

  cast send \
    --rpc-url "${RPC_URL}" \
    --private-key "${PK_PUBLISHER}" \
    --json \
    --create "${deployment_data}" | jq -r '.contractAddress'
}

lower_hex() {
  echo "$1" | tr '[:upper:]' '[:lower:]'
}

for tool in anvil forge cast cargo jq curl sqlite3; do
  require_cmd "${tool}"
done

ANVIL_PORT="${ANVIL_PORT:-8545}"
API_PORT="${API_PORT:-18080}"
RPC_URL="http://127.0.0.1:${ANVIL_PORT}"

PK_PUBLISHER="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

PUBLISHER_ADDR="$(cast wallet address --private-key "${PK_PUBLISHER}")"
DECIDER_ADDR="${CHAIN_SMOKE_DECIDER_ADDR:-0x70997970C51812dc3A010C7d01b50e0d17dc79C8}"
ENDORSER_ADDR="${CHAIN_SMOKE_ENDORSER_ADDR:-0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC}"
TARGET_ADDR="${CHAIN_SMOKE_TARGET_ADDR:-0x90F79bf6EB2c4f870365E785982E1f101E93b906}"

DB_FILE="${TMP_DIR}/trustnet-chain-smoke.db"
DB_URL="sqlite://${DB_FILE}"
INDEXER_CONFIG="${TMP_DIR}/indexer.toml"
ROOT_JSON="${TMP_DIR}/root.json"
DECISION_JSON="${TMP_DIR}/decision.json"

echo "Starting anvil on ${RPC_URL}"
anvil --port "${ANVIL_PORT}" --chain-id 31337 >"${TMP_DIR}/anvil.log" 2>&1 &
ANVIL_PID="$!"
wait_for_rpc

echo "Deploying chain smoke contracts"
pushd "${REPO_ROOT}/solidity" >/dev/null
ROOT_REGISTRY="$(deploy_contract "RootRegistry" "constructor(address)" "${PUBLISHER_ADDR}")"
TRUST_GRAPH="$(deploy_contract "TrustGraph")"
ERC8004_IDENTITY="$(deploy_contract "MockErc8004IdentityRegistry")"
ERC8004_REPUTATION="$(deploy_contract "MockErc8004Reputation")"
popd >/dev/null

echo "RootRegistry: ${ROOT_REGISTRY}"
echo "TrustGraph: ${TRUST_GRAPH}"
echo "ERC8004 Identity: ${ERC8004_IDENTITY}"
echo "ERC8004 Reputation: ${ERC8004_REPUTATION}"

cat >"${INDEXER_CONFIG}" <<EOF
[network]
rpc_url = "${RPC_URL}"
chain_id = 31337

[contracts]
trust_graph = "${TRUST_GRAPH}"
root_registry = "${ROOT_REGISTRY}"
erc8004_reputation = "${ERC8004_REPUTATION}"
erc8004_identity = "${ERC8004_IDENTITY}"

[database]
url = "${DB_URL}"
max_connections = 5
min_connections = 1

[sync]
start_block = 0
poll_interval_secs = 1
batch_size = 1000
confirmations = 0

[builder]
rebuild_interval_secs = 1

[publisher]
auto_publish = false
publish_interval_secs = 3600
private_key = "${PK_PUBLISHER}"
max_fee_per_gas_gwei = 50
max_priority_fee_per_gas_gwei = 2
max_gas_price_gwei = 0
confirmations = 0
max_retries = 3
min_interval_secs = 1

[logging]
level = "info"
format = "pretty"
EOF

echo "Initializing database"
cargo run -q -p trustnet-indexer -- init-db --database-url "${DB_URL}" >/dev/null

echo "Emitting ERC-8004 NewFeedback + ResponseAppended events"
cast send --rpc-url "${RPC_URL}" --private-key "${PK_PUBLISHER}" \
  "${ERC8004_IDENTITY}" "setAgentWallet(uint256,address)" 1001 "${ENDORSER_ADDR}" >/dev/null
cast send --rpc-url "${RPC_URL}" --private-key "${PK_PUBLISHER}" \
  "${ERC8004_IDENTITY}" "setAgentWallet(uint256,address)" 2002 "${TARGET_ADDR}" >/dev/null

cast send --rpc-url "${RPC_URL}" --private-key "${PK_PUBLISHER}" \
  "${ERC8004_REPUTATION}" \
  "emitTrustnetFeedback(uint256,address,uint64,int128,uint8,bytes32)" \
  1001 "${DECIDER_ADDR}" 1 90 0 \
  "0x1111111111111111111111111111111111111111111111111111111111111111" >/dev/null

cast send --rpc-url "${RPC_URL}" --private-key "${PK_PUBLISHER}" \
  "${ERC8004_REPUTATION}" \
  "emitTrustnetFeedback(uint256,address,uint64,int128,uint8,bytes32)" \
  2002 "${ENDORSER_ADDR}" 2 90 0 \
  "0x2222222222222222222222222222222222222222222222222222222222222222" >/dev/null

cast send --rpc-url "${RPC_URL}" --private-key "${PK_PUBLISHER}" \
  "${ERC8004_REPUTATION}" \
  "emitResponseAppendedSimple(uint256,address,uint64,address,bytes32)" \
  2002 "${ENDORSER_ADDR}" 2 "${PUBLISHER_ADDR}" \
  "0x3333333333333333333333333333333333333333333333333333333333333333" >/dev/null

echo "Starting indexer and waiting for chain ingestion"
cargo run -q -p trustnet-indexer -- --config "${INDEXER_CONFIG}" run >"${TMP_DIR}/indexer.log" 2>&1 &
INDEXER_PID="$!"

wait_for_sql_count_at_least "${DB_FILE}" "feedback_raw" 2
wait_for_sql_count_at_least "${DB_FILE}" "feedback_responses_raw" 1
wait_for_sql_count_at_least "${DB_FILE}" "edges_latest" 2

kill "${INDEXER_PID}" >/dev/null 2>&1 || true
wait "${INDEXER_PID}" >/dev/null 2>&1 || true
INDEXER_PID=""

echo "Publishing root on-chain"
cargo run -q -p trustnet-indexer -- --config "${INDEXER_CONFIG}" publish-root >/dev/null

echo "Starting API"
DATABASE_URL="${DB_URL}" \
PORT="${API_PORT}" \
TRUSTNET_API_WRITE_ENABLED=0 \
SMM_CACHE_DIR="${TMP_DIR}/smm_cache" \
cargo run -q -p trustnet-api >"${TMP_DIR}/api.log" 2>&1 &
API_PID="$!"

wait_for_http "http://127.0.0.1:${API_PORT}/v1/contexts"

CONTEXT_ID="$(cast keccak "trustnet:ctx:payments:v1")"
curl -fsS "http://127.0.0.1:${API_PORT}/v1/root" >"${ROOT_JSON}"

decision_attempts=0
while true; do
  code="$(curl -sS -o "${DECISION_JSON}" -w "%{http_code}" \
    "http://127.0.0.1:${API_PORT}/v1/decision?decider=${DECIDER_ADDR}&target=${TARGET_ADDR}&contextId=${CONTEXT_ID}")"
  if [[ "${code}" == "200" ]]; then
    break
  fi
  decision_attempts=$((decision_attempts + 1))
  if ((decision_attempts > 30)); then
    echo "timed out waiting for decision endpoint to return 200" >&2
    exit 1
  fi
  sleep 1
done

echo "Verifying bundle cryptographically"
cargo run -q -p trustnet-cli -- verify \
  --root "${ROOT_JSON}" \
  --bundle "${DECISION_JSON}" \
  --publisher "${PUBLISHER_ADDR}" >/dev/null

echo "Cross-checking root against on-chain RootRegistry"
ROOT_EPOCH="$(jq -r '.epoch' "${ROOT_JSON}")"
ROOT_GRAPH="$(jq -r '.graphRoot | ascii_downcase' "${ROOT_JSON}")"
ROOT_MANIFEST_HASH="$(jq -r '.manifestHash | ascii_downcase' "${ROOT_JSON}")"
ONCHAIN_EPOCH="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "currentEpoch()(uint256)" | tr -d '[:space:]')"
ONCHAIN_ROOT="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "getRootAt(uint256)(bytes32)" "${ROOT_EPOCH}" | tr -d '[:space:]')"
ONCHAIN_MANIFEST_HASH="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "getManifestHashAt(uint256)(bytes32)" "${ROOT_EPOCH}" | tr -d '[:space:]')"

if [[ "${ONCHAIN_EPOCH}" != "${ROOT_EPOCH}" ]]; then
  echo "epoch mismatch: root.json=${ROOT_EPOCH}, rootRegistry=${ONCHAIN_EPOCH}" >&2
  exit 1
fi

if [[ "$(lower_hex "${ONCHAIN_ROOT}")" != "$(lower_hex "${ROOT_GRAPH}")" ]]; then
  echo "graphRoot mismatch against RootRegistry" >&2
  exit 1
fi

if [[ "$(lower_hex "${ONCHAIN_MANIFEST_HASH}")" != "$(lower_hex "${ROOT_MANIFEST_HASH}")" ]]; then
  echo "manifestHash mismatch against RootRegistry" >&2
  exit 1
fi

jq -e \
  --arg expected_endorser_hex "$(lower_hex "${ENDORSER_ADDR#0x}")" \
  --arg expected_root "$(lower_hex "${ROOT_GRAPH}")" \
  --argjson expected_epoch "${ROOT_EPOCH}" \
  '.decision == "allow"
    and .endorser != null
    and (.endorser | ascii_downcase | endswith($expected_endorser_hex))
    and (.graphRoot | ascii_downcase) == $expected_root
    and .epoch == $expected_epoch' \
  "${DECISION_JSON}" >/dev/null

echo
echo "Chain-mode smoke test passed."
echo "  feedback_raw rows:          $(sqlite3 "${DB_FILE}" "SELECT COUNT(*) FROM feedback_raw;")"
echo "  feedback_responses_raw rows: $(sqlite3 "${DB_FILE}" "SELECT COUNT(*) FROM feedback_responses_raw;")"
echo "  edges_latest rows:          $(sqlite3 "${DB_FILE}" "SELECT COUNT(*) FROM edges_latest;")"
echo "  root epoch:                 ${ROOT_EPOCH}"
echo "  root registry:              ${ROOT_REGISTRY}"
