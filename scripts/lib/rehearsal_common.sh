#!/usr/bin/env bash

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_nonempty() {
  local value="$1"
  local label="$2"
  if [[ -z "${value}" ]]; then
    echo "missing required value: ${label}" >&2
    exit 1
  fi
}

validate_address() {
  local value="$1"
  local label="$2"
  if [[ ! "${value}" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo "invalid ${label}: ${value}" >&2
    exit 1
  fi
}

lower_hex() {
  echo "$1" | tr '[:upper:]' '[:lower:]'
}

wait_for_http() {
  local url="$1"
  local attempts=0
  until curl -fsS "${url}" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if ((attempts > 180)); then
      echo "endpoint did not become ready in time: ${url}" >&2
      exit 1
    fi
    sleep 1
  done
}

wait_for_sql_count_at_least() {
  local table="$1"
  local min_count="$2"
  local attempts=0

  while true; do
    local count
    count="$(sqlite3 "${DB_FILE}" "SELECT COUNT(*) FROM ${table};" | tr -d '[:space:]')"
    if [[ "${count}" =~ ^[0-9]+$ ]] && ((count >= min_count)); then
      return 0
    fi
    attempts=$((attempts + 1))
    if ((attempts > 240)); then
      echo "timed out waiting for ${table} count >= ${min_count} (last=${count})" >&2
      exit 1
    fi
    sleep 1
  done
}

wait_for_rpc() {
  local attempts=0
  until cast block-number --rpc-url "${RPC_URL}" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if ((attempts > 60)); then
      echo "RPC did not become ready in time: ${RPC_URL}" >&2
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
    --private-key "${PUBLISHER_PRIVATE_KEY}" \
    --json \
    --create "${deployment_data}" | jq -r '.contractAddress'
}

