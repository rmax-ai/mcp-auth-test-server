#!/usr/bin/env bash

set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8765}"
SCHEMES=(
  no-auth
  bearer-token
  oauth-v1
  oauth-v2-3l
  oauth-v2-2l
  oauth-v21
  dynamic-registration
)

for scheme in "${SCHEMES[@]}"; do
  echo "==> Testing ${scheme} against ${BASE_URL}"
  python tests/test_client.py --base-url "${BASE_URL}" --scheme "${scheme}"
done
