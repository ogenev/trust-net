#!/usr/bin/env bash

start_api() {
  DATABASE_URL="${DB_URL}" \
  PORT="${API_PORT}" \
  TRUSTNET_API_WRITE_ENABLED=0 \
  SMM_CACHE_DIR="${SMM_CACHE_DIR}" \
  cargo run -q -p trustnet-api >"${API_LOG}" 2>&1 &
  API_PID="$!"
  wait_for_http "http://127.0.0.1:${API_PORT}/v1/contexts"
}

start_indexer() {
  TRUSTNET_VERIFY_RESPONSES="${VERIFY_RESPONSES}" \
  cargo run -q -p trustnet-indexer -- --config "${INDEXER_CONFIG}" run >"${INDEXER_LOG}" 2>&1 &
  INDEXER_PID="$!"
}

stop_indexer() {
  if [[ -z "${INDEXER_PID}" ]]; then
    return
  fi
  kill "${INDEXER_PID}" >/dev/null 2>&1 || true
  wait "${INDEXER_PID}" >/dev/null 2>&1 || true
  INDEXER_PID=""
}

crash_indexer() {
  if [[ -z "${INDEXER_PID}" ]]; then
    return
  fi
  kill -9 "${INDEXER_PID}" >/dev/null 2>&1 || true
  wait "${INDEXER_PID}" >/dev/null 2>&1 || true
  INDEXER_PID=""
}

publish_root() {
  cargo run -q -p trustnet-indexer -- --config "${INDEXER_CONFIG}" publish-root >>"${PUBLISH_LOG}" 2>&1
}

write_indexer_config() {
  cat >"${INDEXER_CONFIG}" <<EOF
[network]
rpc_url = "${RPC_URL}"
chain_id = ${CHAIN_ID}

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
start_block = ${START_BLOCK}
poll_interval_secs = 2
batch_size = 1000
confirmations = ${SYNC_CONFIRMATIONS}

[builder]
rebuild_interval_secs = 2

[publisher]
auto_publish = false
publish_interval_secs = 3600
private_key = "${PUBLISHER_PRIVATE_KEY}"
max_fee_per_gas_gwei = 20
max_priority_fee_per_gas_gwei = 2
max_gas_price_gwei = 0
confirmations = ${PUBLISHER_CONFIRMATIONS}
max_retries = 3
min_interval_secs = 1
manifest_output_dir = "${MANIFEST_OUTPUT_DIR}"
manifest_public_base_uri = "${MANIFEST_PUBLIC_BASE_URI}"

[logging]
level = "info"
format = "pretty"
EOF
}

send_tx_json() {
  local private_key="$1"
  shift
  cast send --rpc-url "${RPC_URL}" --private-key "${private_key}" --json "$@"
}

extract_tx_hash() {
  local receipt_json="$1"
  local tx_hash
  tx_hash="$(jq -r '.transactionHash // empty' <<<"${receipt_json}")"
  require_nonempty "${tx_hash}" "transactionHash"
  echo "${tx_hash}"
}

register_agent_if_missing() {
  local current_id="$1"
  local owner_pk="$2"
  local owner_addr="$3"
  local agent_uri="$4"
  local tx_hash_out_var="$5"

  if [[ -n "${current_id}" ]]; then
    echo "${current_id}"
    return
  fi

  local receipt
  receipt="$(send_tx_json "${owner_pk}" "${ERC8004_IDENTITY}" "register(string)(uint256)" "${agent_uri}")"
  local tx_hash
  tx_hash="$(extract_tx_hash "${receipt}")"
  printf -v "${tx_hash_out_var}" '%s' "${tx_hash}"

  local topic_agent_id
  topic_agent_id="$(jq -r --arg sig "${REGISTERED_SIG}" \
    '.logs[]? | select((.topics[0] | ascii_downcase) == $sig) | .topics[1]' <<<"${receipt}" | head -n1)"
  require_nonempty "${topic_agent_id}" "Registered(agentId) topic"

  cast to-dec "${topic_agent_id}" | tr -d '[:space:]'
}

ensure_agent_wallet_binding() {
  local agent_id="$1"
  local expected_wallet="$2"
  local agent_wallet
  agent_wallet="$(cast call --rpc-url "${RPC_URL}" "${ERC8004_IDENTITY}" \
    "getAgentWallet(uint256)(address)" "${agent_id}" | tr -d '[:space:]')"
  require_nonempty "${agent_wallet}" "getAgentWallet(${agent_id})"

  if [[ "$(lower_hex "${agent_wallet}")" != "$(lower_hex "${expected_wallet}")" ]]; then
    echo "agent ${agent_id} wallet mismatch: expected=${expected_wallet}, got=${agent_wallet}" >&2
    exit 1
  fi
}

cross_check_epoch_against_chain() {
  local epoch="$1"

  local db_graph
  local db_manifest_hash
  local db_manifest_uri
  db_graph="$(sqlite3 "${DB_FILE}" "SELECT graph_root FROM epochs WHERE epoch = ${epoch};" | tr -d '[:space:]')"
  db_manifest_hash="$(sqlite3 "${DB_FILE}" "SELECT manifest_hash FROM epochs WHERE epoch = ${epoch};" | tr -d '[:space:]')"
  db_manifest_uri="$(sqlite3 "${DB_FILE}" "SELECT manifest_uri FROM epochs WHERE epoch = ${epoch};" | tr -d '\r\n')"

  require_nonempty "${db_graph}" "epochs.graph_root for epoch ${epoch}"
  require_nonempty "${db_manifest_hash}" "epochs.manifest_hash for epoch ${epoch}"
  require_nonempty "${db_manifest_uri}" "epochs.manifest_uri for epoch ${epoch}"
  if [[ "${db_manifest_uri}" == "inline" ]]; then
    echo "epoch ${epoch}: manifest_uri must not be inline" >&2
    exit 1
  fi

  local onchain_root
  local onchain_manifest_hash
  local onchain_manifest_uri
  onchain_root="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "getRootAt(uint256)(bytes32)" "${epoch}" | tr -d '[:space:]')"
  onchain_manifest_hash="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "getManifestHashAt(uint256)(bytes32)" "${epoch}" | tr -d '[:space:]')"
  onchain_manifest_uri="$(cast call --rpc-url "${RPC_URL}" "${ROOT_REGISTRY}" "getManifestURIAt(uint256)(string)" "${epoch}" | tr -d '\r\n' | sed -e 's/^"//' -e 's/"$//')"

  if [[ "$(lower_hex "${db_graph}")" != "$(lower_hex "${onchain_root}")" ]]; then
    echo "epoch ${epoch}: graphRoot mismatch against RootRegistry" >&2
    exit 1
  fi
  if [[ "$(lower_hex "${db_manifest_hash}")" != "$(lower_hex "${onchain_manifest_hash}")" ]]; then
    echo "epoch ${epoch}: manifestHash mismatch against RootRegistry" >&2
    exit 1
  fi
  if [[ "${db_manifest_uri}" != "${onchain_manifest_uri}" ]]; then
    echo "epoch ${epoch}: manifestUri mismatch against RootRegistry" >&2
    exit 1
  fi
}

emit_phase1_events() {
  local de_receipt
  de_receipt="$(send_tx_json "${DECIDER_PRIVATE_KEY}" "${ERC8004_REPUTATION}" \
    "giveFeedback(uint256,int128,uint8,string,string,string,string,bytes32)" \
    "${ENDORSER_AGENT_ID}" 90 0 \
    "${CONTEXT_LABEL}" "${TAG2_LABEL}" "${ENDPOINT_LABEL}" "${FEEDBACK_URI_D_E}" "${FEEDBACK_HASH_D_E}")"
  TX_FEEDBACK_DE="$(extract_tx_hash "${de_receipt}")"

  local et_receipt
  et_receipt="$(send_tx_json "${ENDORSER_PRIVATE_KEY}" "${ERC8004_REPUTATION}" \
    "giveFeedback(uint256,int128,uint8,string,string,string,string,bytes32)" \
    "${TARGET_AGENT_ID}" 90 0 \
    "${CONTEXT_LABEL}" "${TAG2_LABEL}" "${ENDPOINT_LABEL}" "${FEEDBACK_URI_E_T_PHASE1}" "${FEEDBACK_HASH_E_T_PHASE1}")"
  TX_FEEDBACK_ET_PHASE1="$(extract_tx_hash "${et_receipt}")"

  local et_feedback_index
  et_feedback_index="$(cast call --rpc-url "${RPC_URL}" "${ERC8004_REPUTATION}" \
    "getLastIndex(uint256,address)(uint64)" "${TARGET_AGENT_ID}" "${ENDORSER_ADDR}" | tr -d '[:space:]')"
  require_nonempty "${et_feedback_index}" "phase1 E->T feedback index"

  local response_receipt
  response_receipt="$(send_tx_json "${PUBLISHER_PRIVATE_KEY}" "${ERC8004_REPUTATION}" \
    "appendResponse(uint256,address,uint64,string,bytes32)" \
    "${TARGET_AGENT_ID}" "${ENDORSER_ADDR}" "${et_feedback_index}" "${RESPONSE_URI_PHASE1}" "${RESPONSE_HASH_PHASE1}")"
  TX_RESPONSE_PHASE1="$(extract_tx_hash "${response_receipt}")"
}

emit_phase2_events() {
  local et_receipt
  et_receipt="$(send_tx_json "${ENDORSER_PRIVATE_KEY}" "${ERC8004_REPUTATION}" \
    "giveFeedback(uint256,int128,uint8,string,string,string,string,bytes32)" \
    "${TARGET_AGENT_ID}" 85 0 \
    "${CONTEXT_LABEL}" "${TAG2_LABEL}" "${ENDPOINT_LABEL}" "${FEEDBACK_URI_E_T_PHASE2}" "${FEEDBACK_HASH_E_T_PHASE2}")"
  TX_FEEDBACK_ET_PHASE2="$(extract_tx_hash "${et_receipt}")"

  local et_feedback_index
  et_feedback_index="$(cast call --rpc-url "${RPC_URL}" "${ERC8004_REPUTATION}" \
    "getLastIndex(uint256,address)(uint64)" "${TARGET_AGENT_ID}" "${ENDORSER_ADDR}" | tr -d '[:space:]')"
  require_nonempty "${et_feedback_index}" "phase2 E->T feedback index"

  local response_receipt
  response_receipt="$(send_tx_json "${PUBLISHER_PRIVATE_KEY}" "${ERC8004_REPUTATION}" \
    "appendResponse(uint256,address,uint64,string,bytes32)" \
    "${TARGET_AGENT_ID}" "${ENDORSER_ADDR}" "${et_feedback_index}" "${RESPONSE_URI_PHASE2}" "${RESPONSE_HASH_PHASE2}")"
  TX_RESPONSE_PHASE2="$(extract_tx_hash "${response_receipt}")"
}

