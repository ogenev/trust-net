#!/usr/bin/env -S NO_PROXY=* HTTPS_PROXY= HTTP_PROXY= ALL_PROXY= bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

PROFILE_PATH="${TRUSTNET_RELEASE_PROFILE:-${SCRIPT_DIR}/base_sepolia_release.env}"
if [[ ! -f "${PROFILE_PATH}" ]]; then
  echo "missing release profile: ${PROFILE_PATH}" >&2
  echo "copy scripts/base_sepolia_release.env.example to scripts/base_sepolia_release.env first" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${PROFILE_PATH}"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/rehearsal_common.sh"

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_DIR="${TRUSTNET_ARTIFACT_DIR:-${REPO_ROOT}/artifacts/dress-rehearsal/base-sepolia-public-${RUN_TS}}"
mkdir -p "${ARTIFACT_DIR}"

API_LOG="${ARTIFACT_DIR}/api.log"
INDEXER_LOG="${ARTIFACT_DIR}/indexer.log"
PUBLISH_LOG="${ARTIFACT_DIR}/publish.log"
REPORT_JSON="${ARTIFACT_DIR}/report.json"
ROOT_JSON="${ARTIFACT_DIR}/root.json"
SCORE_JSON="${ARTIFACT_DIR}/score.json"
INDEXER_CONFIG="${ARTIFACT_DIR}/indexer.base-sepolia.toml"

DB_FILE="${TRUSTNET_DB_FILE:-${ARTIFACT_DIR}/trustnet-base-sepolia.db}"
DB_DIR="$(dirname -- "${DB_FILE}")"
mkdir -p "${DB_DIR}"
DB_URL="sqlite://${DB_FILE}"

MANIFEST_OUTPUT_DIR="${TRUSTNET_MANIFEST_OUTPUT_DIR:-${ARTIFACT_DIR}/manifests}"
mkdir -p "${MANIFEST_OUTPUT_DIR}"
MANIFEST_PUBLIC_BASE_URI="${TRUSTNET_MANIFEST_PUBLIC_BASE_URI:-}"

SMM_CACHE_DIR="${TRUSTNET_SMM_CACHE_DIR:-${ARTIFACT_DIR}/smm_cache}"
mkdir -p "${SMM_CACHE_DIR}"

CHAIN_ID="${TRUSTNET_CHAIN_ID:-84532}"
RPC_URL="${TRUSTNET_RPC_URL:-}"
API_PORT="${TRUSTNET_API_PORT:-18088}"
SYNC_CONFIRMATIONS="${TRUSTNET_SYNC_CONFIRMATIONS:-2}"
PUBLISHER_CONFIRMATIONS="${TRUSTNET_PUBLISHER_CONFIRMATIONS:-1}"
START_BLOCK="${TRUSTNET_START_BLOCK:-}"
VERIFY_RESPONSES="${TRUSTNET_VERIFY_RESPONSES:-0}"

ROOT_REGISTRY="${TRUSTNET_ROOT_REGISTRY:-}"
TRUST_GRAPH="${TRUSTNET_TRUST_GRAPH:-}"
ERC8004_IDENTITY="${TRUSTNET_ERC8004_IDENTITY:-0x8004A818BFB912233c491871b3d84c89A494BD9e}"
ERC8004_REPUTATION="${TRUSTNET_ERC8004_REPUTATION:-0x8004B663056A597Dffe9eCcC1965A193B7388713}"

PUBLISHER_PRIVATE_KEY="${TRUSTNET_PUBLISHER_PRIVATE_KEY:-}"
DECIDER_PRIVATE_KEY="${TRUSTNET_DECIDER_PRIVATE_KEY:-}"
ENDORSER_PRIVATE_KEY="${TRUSTNET_ENDORSER_PRIVATE_KEY:-}"
TARGET_PRIVATE_KEY="${TRUSTNET_TARGET_PRIVATE_KEY:-}"

CONTEXT_LABEL="${TRUSTNET_REHEARSAL_CONTEXT:-trustnet:ctx:code-exec:v1}"
TAG2_LABEL="${TRUSTNET_REHEARSAL_TAG2:-trustnet:v1}"
ENDPOINT_LABEL="${TRUSTNET_REHEARSAL_ENDPOINT:-trustnet}"

ENDORSER_AGENT_ID="${TRUSTNET_ENDORSER_AGENT_ID:-}"
TARGET_AGENT_ID="${TRUSTNET_TARGET_AGENT_ID:-}"

ENDORSER_AGENT_URI="${TRUSTNET_ENDORSER_AGENT_URI:-https://example.com/trustnet/rehearsal/${RUN_TS}/endorser.json}"
TARGET_AGENT_URI="${TRUSTNET_TARGET_AGENT_URI:-https://example.com/trustnet/rehearsal/${RUN_TS}/target.json}"

FEEDBACK_URI_D_E="${TRUSTNET_FEEDBACK_URI_DE:-}"
FEEDBACK_URI_E_T_PHASE1="${TRUSTNET_FEEDBACK_URI_ET_PHASE1:-}"
FEEDBACK_URI_E_T_PHASE2="${TRUSTNET_FEEDBACK_URI_ET_PHASE2:-}"
RESPONSE_URI_PHASE1="${TRUSTNET_RESPONSE_URI_PHASE1:-}"
RESPONSE_URI_PHASE2="${TRUSTNET_RESPONSE_URI_PHASE2:-}"

FEEDBACK_HASH_D_E="${TRUSTNET_FEEDBACK_HASH_DE:-0x1111111111111111111111111111111111111111111111111111111111111111}"
FEEDBACK_HASH_E_T_PHASE1="${TRUSTNET_FEEDBACK_HASH_ET_PHASE1:-0x2222222222222222222222222222222222222222222222222222222222222222}"
RESPONSE_HASH_PHASE1="${TRUSTNET_RESPONSE_HASH_PHASE1:-0x3333333333333333333333333333333333333333333333333333333333333333}"
FEEDBACK_HASH_E_T_PHASE2="${TRUSTNET_FEEDBACK_HASH_ET_PHASE2:-0x4444444444444444444444444444444444444444444444444444444444444444}"
RESPONSE_HASH_PHASE2="${TRUSTNET_RESPONSE_HASH_PHASE2:-0x5555555555555555555555555555555555555555555555555555555555555555}"

INDEXER_PID=""
API_PID=""

REGISTERED_SIG=""

DECIDER_ADDR=""
ENDORSER_ADDR=""
TARGET_ADDR=""
PUBLISHER_ADDR=""

TX_REGISTER_ENDORSER=""
TX_REGISTER_TARGET=""
TX_FEEDBACK_DE=""
TX_FEEDBACK_ET_PHASE1=""
TX_RESPONSE_PHASE1=""
TX_FEEDBACK_ET_PHASE2=""
TX_RESPONSE_PHASE2=""

cleanup() {
  set +e

  if [[ -n "${API_PID}" ]]; then
    kill "${API_PID}" >/dev/null 2>&1 || true
    wait "${API_PID}" >/dev/null 2>&1 || true
    API_PID=""
  fi
  if [[ -n "${INDEXER_PID}" ]]; then
    kill "${INDEXER_PID}" >/dev/null 2>&1 || true
    wait "${INDEXER_PID}" >/dev/null 2>&1 || true
    INDEXER_PID=""
  fi
}
trap cleanup EXIT

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/base_sepolia_public_lib.sh"

for tool in cast cargo jq curl sqlite3; do
  require_cmd "${tool}"
done

require_nonempty "${RPC_URL}" "TRUSTNET_RPC_URL"
require_nonempty "${ROOT_REGISTRY}" "TRUSTNET_ROOT_REGISTRY"
require_nonempty "${TRUST_GRAPH}" "TRUSTNET_TRUST_GRAPH"
require_nonempty "${MANIFEST_PUBLIC_BASE_URI}" "TRUSTNET_MANIFEST_PUBLIC_BASE_URI"

require_nonempty "${PUBLISHER_PRIVATE_KEY}" "TRUSTNET_PUBLISHER_PRIVATE_KEY"
require_nonempty "${DECIDER_PRIVATE_KEY}" "TRUSTNET_DECIDER_PRIVATE_KEY"
require_nonempty "${ENDORSER_PRIVATE_KEY}" "TRUSTNET_ENDORSER_PRIVATE_KEY"
require_nonempty "${TARGET_PRIVATE_KEY}" "TRUSTNET_TARGET_PRIVATE_KEY"

validate_address "${ROOT_REGISTRY}" "TRUSTNET_ROOT_REGISTRY"
validate_address "${TRUST_GRAPH}" "TRUSTNET_TRUST_GRAPH"
validate_address "${ERC8004_IDENTITY}" "TRUSTNET_ERC8004_IDENTITY"
validate_address "${ERC8004_REPUTATION}" "TRUSTNET_ERC8004_REPUTATION"

wait_for_rpc
if [[ "$(cast chain-id --rpc-url "${RPC_URL}" | tr -d '[:space:]')" != "${CHAIN_ID}" ]]; then
  echo "rpc chain-id mismatch; expected ${CHAIN_ID}" >&2
  exit 1
fi
if [[ "${CHAIN_ID}" != "84532" ]]; then
  echo "invalid TRUSTNET_CHAIN_ID=${CHAIN_ID}; this script is locked to Base Sepolia (84532)" >&2
  exit 1
fi

REGISTERED_SIG="$(cast keccak "Registered(uint256,string,address)" | tr '[:upper:]' '[:lower:]')"
PUBLISHER_ADDR="$(cast wallet address --private-key "${PUBLISHER_PRIVATE_KEY}")"
DECIDER_ADDR="$(cast wallet address --private-key "${DECIDER_PRIVATE_KEY}")"
ENDORSER_ADDR="$(cast wallet address --private-key "${ENDORSER_PRIVATE_KEY}")"
TARGET_ADDR="$(cast wallet address --private-key "${TARGET_PRIVATE_KEY}")"

validate_address "${PUBLISHER_ADDR}" "publisher address"
validate_address "${DECIDER_ADDR}" "decider address"
validate_address "${ENDORSER_ADDR}" "endorser address"
validate_address "${TARGET_ADDR}" "target address"

if [[ -z "${START_BLOCK}" ]]; then
  START_BLOCK="$(cast block-number --rpc-url "${RPC_URL}" | tr -d '[:space:]')"
fi
require_nonempty "${START_BLOCK}" "TRUSTNET_START_BLOCK"

echo "Initializing database and writing config"
cargo run -q -p trustnet-indexer -- init-db --database-url "${DB_URL}" >/dev/null
write_indexer_config

echo "Starting API and indexer"
start_api
start_indexer

echo "Preparing agents on public IdentityRegistry"
ENDORSER_AGENT_ID="$(register_agent_if_missing "${ENDORSER_AGENT_ID}" "${ENDORSER_PRIVATE_KEY}" "${ENDORSER_ADDR}" "${ENDORSER_AGENT_URI}" TX_REGISTER_ENDORSER)"
TARGET_AGENT_ID="$(register_agent_if_missing "${TARGET_AGENT_ID}" "${TARGET_PRIVATE_KEY}" "${TARGET_ADDR}" "${TARGET_AGENT_URI}" TX_REGISTER_TARGET)"

ensure_agent_wallet_binding "${ENDORSER_AGENT_ID}" "${ENDORSER_ADDR}"
ensure_agent_wallet_binding "${TARGET_AGENT_ID}" "${TARGET_ADDR}"

echo "Emitting phase 1 real ERC-8004 traffic"
emit_phase1_events
wait_for_sql_count_at_least "feedback_raw" 2
wait_for_sql_count_at_least "feedback_responses_raw" 1
wait_for_sql_count_at_least "edges_latest" 2

echo "Publishing epoch 1 root"
stop_indexer
publish_root
EPOCH1="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "currentEpoch()(uint256)" | tr -d '[:space:]')"
cross_check_epoch_against_chain "${EPOCH1}"

echo "Phase 2 crash/restart rehearsal"
start_indexer
emit_phase2_events
sleep 1
crash_indexer

start_indexer
wait_for_sql_count_at_least "feedback_raw" 3
wait_for_sql_count_at_least "feedback_responses_raw" 2
wait_for_sql_count_at_least "edges_latest" 2

echo "Publishing epoch 2 root"
stop_indexer
publish_root
EPOCH2="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "currentEpoch()(uint256)" | tr -d '[:space:]')"
if ((EPOCH2 <= EPOCH1)); then
  echo "expected epoch to advance (epoch1=${EPOCH1}, epoch2=${EPOCH2})" >&2
  exit 1
fi
cross_check_epoch_against_chain "${EPOCH2}"

echo "Fetching root + score from API"
curl -fsS "http://127.0.0.1:${API_PORT}/v1/root" >"${ROOT_JSON}"

score_attempts=0
while true; do
  code="$(curl -sS -o "${SCORE_JSON}" -w "%{http_code}" \
    "http://127.0.0.1:${API_PORT}/v1/score/${DECIDER_ADDR}/${TARGET_ADDR}?contextTag=${CONTEXT_LABEL}")"
  if [[ "${code}" == "200" ]]; then
    break
  fi
  score_attempts=$((score_attempts + 1))
  if ((score_attempts > 90)); then
    echo "timed out waiting for score endpoint to return 200" >&2
    exit 1
  fi
  sleep 1
done

ROOT_EPOCH="$(jq -r '.epoch' "${ROOT_JSON}")"
ROOT_GRAPH="$(jq -r '.graphRoot | ascii_downcase' "${ROOT_JSON}")"
ROOT_MANIFEST_HASH="$(jq -r '.manifestHash | ascii_downcase' "${ROOT_JSON}")"
ROOT_MANIFEST_URI="$(jq -r '.manifestUri // empty' "${ROOT_JSON}")"

if [[ -z "${ROOT_MANIFEST_URI}" || "${ROOT_MANIFEST_URI}" == "inline" ]]; then
  echo "manifestUri is missing or inline in /v1/root" >&2
  exit 1
fi

ONCHAIN_ROOT="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "getRootAt(uint256)(bytes32)" "${ROOT_EPOCH}" | tr -d '[:space:]')"
ONCHAIN_MANIFEST_HASH="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "getManifestHashAt(uint256)(bytes32)" "${ROOT_EPOCH}" | tr -d '[:space:]')"
ONCHAIN_MANIFEST_URI="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "getManifestURIAt(uint256)(string)" "${ROOT_EPOCH}" | tr -d '\r\n' | sed -e 's/^"//' -e 's/"$//')"

if [[ "$(lower_hex "${ONCHAIN_ROOT}")" != "$(lower_hex "${ROOT_GRAPH}")" ]]; then
  echo "latest root graphRoot mismatch between API and RootRegistry" >&2
  exit 1
fi
if [[ "$(lower_hex "${ONCHAIN_MANIFEST_HASH}")" != "$(lower_hex "${ROOT_MANIFEST_HASH}")" ]]; then
  echo "latest root manifestHash mismatch between API and RootRegistry" >&2
  exit 1
fi
if [[ "${ONCHAIN_MANIFEST_URI}" != "${ROOT_MANIFEST_URI}" ]]; then
  echo "latest root manifestUri mismatch between API and RootRegistry" >&2
  exit 1
fi

echo "Running anchored score verification"
cargo run -q -p trustnet-cli -- verify \
  --root "${ROOT_JSON}" \
  --bundle "${SCORE_JSON}" \
  --publisher "${PUBLISHER_ADDR}" \
  --rpc-url "${RPC_URL}" \
  --root-registry "${ROOT_REGISTRY}" \
  --epoch "${ROOT_EPOCH}" >/dev/null

jq -e \
  --arg expected_endorser_hex "$(lower_hex "${ENDORSER_ADDR#0x}")" \
  --arg expected_root "$(lower_hex "${ROOT_GRAPH}")" \
  --argjson expected_epoch "${ROOT_EPOCH}" \
  '.score >= 1
    and .proof.endorser != null
    and (.proof.endorser | ascii_downcase | endswith($expected_endorser_hex))
    and (.proof.graphRoot | ascii_downcase) == $expected_root
    and .epoch == $expected_epoch' \
  "${SCORE_JSON}" >/dev/null

FEEDBACK_RAW_COUNT="$(sqlite3 "${DB_FILE}" "SELECT COUNT(*) FROM feedback_raw;" | tr -d '[:space:]')"
RESPONSES_RAW_COUNT="$(sqlite3 "${DB_FILE}" "SELECT COUNT(*) FROM feedback_responses_raw;" | tr -d '[:space:]')"
EDGES_LATEST_COUNT="$(sqlite3 "${DB_FILE}" "SELECT COUNT(*) FROM edges_latest;" | tr -d '[:space:]')"

cat >"${REPORT_JSON}" <<EOF
{
  "network": "base-sepolia",
  "mode": "public-erc8004",
  "chainId": ${CHAIN_ID},
  "rpcUrl": "${RPC_URL}",
  "startBlock": ${START_BLOCK},
  "context": "${CONTEXT_LABEL}",
  "publisherAddress": "${PUBLISHER_ADDR}",
  "deciderAddress": "${DECIDER_ADDR}",
  "endorserAddress": "${ENDORSER_ADDR}",
  "targetAddress": "${TARGET_ADDR}",
  "agents": {
    "endorserAgentId": ${ENDORSER_AGENT_ID},
    "targetAgentId": ${TARGET_AGENT_ID}
  },
  "contracts": {
    "rootRegistry": "${ROOT_REGISTRY}",
    "trustGraph": "${TRUST_GRAPH}",
    "erc8004Identity": "${ERC8004_IDENTITY}",
    "erc8004Reputation": "${ERC8004_REPUTATION}"
  },
  "transactions": {
    "registerEndorserAgent": "${TX_REGISTER_ENDORSER}",
    "registerTargetAgent": "${TX_REGISTER_TARGET}",
    "feedbackDeciderToEndorser": "${TX_FEEDBACK_DE}",
    "feedbackEndorserToTargetPhase1": "${TX_FEEDBACK_ET_PHASE1}",
    "appendResponsePhase1": "${TX_RESPONSE_PHASE1}",
    "feedbackEndorserToTargetPhase2": "${TX_FEEDBACK_ET_PHASE2}",
    "appendResponsePhase2": "${TX_RESPONSE_PHASE2}"
  },
  "epochs": {
    "firstPublishedEpoch": ${EPOCH1},
    "secondPublishedEpoch": ${EPOCH2}
  },
  "checks": {
    "apiRootCrossCheckedWithChain": true,
    "scoreBundleAnchoredVerify": true,
    "indexerCrashRecoveryCatchup": true
  },
  "ingestionCounts": {
    "feedbackRaw": ${FEEDBACK_RAW_COUNT},
    "feedbackResponsesRaw": ${RESPONSES_RAW_COUNT},
    "edgesLatest": ${EDGES_LATEST_COUNT}
  },
  "artifacts": {
    "rootJson": "${ROOT_JSON}",
    "scoreJson": "${SCORE_JSON}",
    "apiLog": "${API_LOG}",
    "indexerLog": "${INDEXER_LOG}",
    "publishLog": "${PUBLISH_LOG}"
  }
}
EOF

echo
echo "Base Sepolia public rehearsal passed."
echo "  Artifact dir:                ${ARTIFACT_DIR}"
echo "  feedback_raw rows:           ${FEEDBACK_RAW_COUNT}"
echo "  feedback_responses_raw rows: ${RESPONSES_RAW_COUNT}"
echo "  edges_latest rows:           ${EDGES_LATEST_COUNT}"
echo "  epoch 1:                     ${EPOCH1}"
echo "  epoch 2:                     ${EPOCH2}"
echo "  report:                      ${REPORT_JSON}"
