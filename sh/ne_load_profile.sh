#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/db_env.sh"
network_encryptor_load_db_env

SQL_DIR="${NETWORK_ENCRYPTOR_ROOT}/sql_options"

usage() {
  echo "Usage: $0 <ne_profiles.id> [basename.sql]"
  echo "  Seed: ${SQL_DIR}/<NN>_*.sql"
  echo "  Example: $0 30"
  echo "  Example: $0 30 30_ssh_l3_ne2_peer.sql"
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  usage
  exit 1
fi

PROFILE_ID="$1"
if ! [[ "${PROFILE_ID}" =~ ^[0-9]+$ ]]; then
  echo "profile_id must be a non-negative integer (ne_profiles.id)" >&2
  exit 1
fi

ID_PADDED=$(printf "%02d" "$((10#${PROFILE_ID}))")

if [ "$#" -eq 2 ]; then
  SQL_BASENAME="$2"
  if [[ "${SQL_BASENAME}" == *"/"* ]] || [[ "${SQL_BASENAME}" == *".."* ]]; then
    echo "Second arg must be a basename only: ${SQL_BASENAME}" >&2
    exit 1
  fi
  SQL_FILE="${SQL_DIR}/${SQL_BASENAME}"
  if [ ! -f "${SQL_FILE}" ]; then
    echo "SQL file not found: ${SQL_FILE}" >&2
    exit 1
  fi
else
  SQL_FILE_GLOB="${SQL_DIR}/${ID_PADDED}_*.sql"
  shopt -s nullglob
  SQL_FILES=( ${SQL_FILE_GLOB} )
  shopt -u nullglob
  if [ "${#SQL_FILES[@]}" -eq 0 ]; then
    echo "No SQL for profile_id=${PROFILE_ID} (glob ${SQL_FILE_GLOB})" >&2
    exit 1
  fi
  IFS=$'\n' SQL_FILES_SORTED=($(printf '%s\n' "${SQL_FILES[@]}" | sort))
  unset IFS
  if [ "${#SQL_FILES_SORTED[@]}" -gt 1 ]; then
    echo "Multiple files match; pass basename. Matches:" >&2
    printf '  %s\n' "${SQL_FILES_SORTED[@]}" >&2
    exit 1
  fi
  SQL_FILE="${SQL_FILES_SORTED[0]}"
fi

echo "=== ne_load_profile ==="
echo "postgres://${POSTGRES_USER}@${POSTGRES_SERVER}:${POSTGRES_PORT}/${POSTGRES_DB}"
echo "ne_profiles.id=${PROFILE_ID}  seed=${SQL_FILE}"
echo

ne_psql -t -A -c "SELECT 1 FROM ne_profiles LIMIT 0;" >/dev/null 2>&1 || {
  echo "[FATAL] ne_profiles missing — run: sh/ne_init_db.sh" >&2
  exit 1
}

ne_psql_file "${SQL_FILE}"

echo "OK loaded ne_profiles.id=${PROFILE_ID} into Database"
