#!/usr/bin/env bash
# Uploads and publishes a packaged zip to Microsoft Edge Add-ons via the Partner
# Center Publish API (v1.1 — the only version still supported; v1 retired end of
# 2024). Requires EDGE_CLIENT_ID, EDGE_API_KEY and EDGE_PRODUCT_ID in the
# environment. See docs/RELEASE.md for how to obtain them.
#
# Per https://learn.microsoft.com/microsoft-edge/extensions/update/api/using-addons-api
# the upload and publish operations each have their own status-check URL — they are
# not interchangeable:
#   upload status:  GET .../submissions/draft/package/operations/{operationId}
#   publish status: GET .../submissions/operations/{operationId}
set -euo pipefail

ZIP_PATH="${1:?usage: publish-edge.sh <path-to-zip>}"

: "${EDGE_CLIENT_ID:?EDGE_CLIENT_ID is not set}"
: "${EDGE_API_KEY:?EDGE_API_KEY is not set}"
: "${EDGE_PRODUCT_ID:?EDGE_PRODUCT_ID is not set}"

API_ROOT="https://api.addons.microsoftedge.microsoft.com/v1/products/${EDGE_PRODUCT_ID}"

curl_auth() {
  curl -sS -H "Authorization: ApiKey ${EDGE_API_KEY}" -H "X-ClientID: ${EDGE_CLIENT_ID}" "$@"
}

# Polls a status URL until it reports Succeeded or Failed (up to ~5 minutes).
wait_for_operation() {
  local status_url="$1"
  local response status
  for _ in $(seq 1 30); do
    sleep 10
    response=$(curl_auth "$status_url")
    status=$(echo "$response" | jq -r '.status // empty')
    case "$status" in
      Succeeded)
        return 0
        ;;
      Failed)
        echo "Edge Add-ons operation at ${status_url} failed:" >&2
        echo "$response" >&2
        return 1
        ;;
      *)
        echo "  ...status: ${status:-unknown}, waiting"
        ;;
    esac
  done
  echo "Edge Add-ons operation at ${status_url} did not complete in time" >&2
  return 1
}

# The API returns the operation id in the Location response header. Under
# `pipefail`, grep finding no match (e.g. an error response with no Location
# header) would otherwise abort the whole script before the caller's own
# "did not return an operation id" diagnostic can run — the `|| true` keeps
# that a clean empty result instead.
operation_id_from_headers() {
  { grep -i '^location:' || true; } | sed -E 's/^[Ll]ocation:[[:space:]]*//' | tr -d '\r\n' | sed -E 's#.*/##'
}

echo "Uploading ${ZIP_PATH} to Edge Add-ons product ${EDGE_PRODUCT_ID}..."
UPLOAD_HEADERS=$(curl_auth -D - -o /dev/null -X POST \
  -H "Content-Type: application/zip" \
  --data-binary "@${ZIP_PATH}" \
  "${API_ROOT}/submissions/draft/package")

UPLOAD_OPERATION_ID=$(echo "$UPLOAD_HEADERS" | operation_id_from_headers)
if [ -z "$UPLOAD_OPERATION_ID" ]; then
  echo "Edge Add-ons upload did not return an operation id:" >&2
  echo "$UPLOAD_HEADERS" >&2
  exit 1
fi

echo "Waiting for Edge Add-ons upload operation ${UPLOAD_OPERATION_ID}..."
wait_for_operation "${API_ROOT}/submissions/draft/package/operations/${UPLOAD_OPERATION_ID}"

echo "Publishing Edge Add-ons draft for product ${EDGE_PRODUCT_ID}..."
NOTES_JSON=$(jq -n --arg notes "Automated release via GitHub Actions." '{notes: $notes}')
PUBLISH_HEADERS=$(curl_auth -D - -o /dev/null -X POST \
  -H "Content-Type: application/json" \
  -d "$NOTES_JSON" \
  "${API_ROOT}/submissions")

PUBLISH_OPERATION_ID=$(echo "$PUBLISH_HEADERS" | operation_id_from_headers)
if [ -z "$PUBLISH_OPERATION_ID" ]; then
  echo "Edge Add-ons publish did not return an operation id:" >&2
  echo "$PUBLISH_HEADERS" >&2
  exit 1
fi

echo "Waiting for Edge Add-ons publish operation ${PUBLISH_OPERATION_ID}..."
wait_for_operation "${API_ROOT}/submissions/operations/${PUBLISH_OPERATION_ID}"

echo "Edge Add-ons: published successfully."
