#!/usr/bin/env bash
# Uploads and publishes a packaged zip to the Chrome Web Store via API v2
# (chromewebstore.googleapis.com) — v1 (www.googleapis.com/chromewebstore/v1.1)
# stops working 2026-10-15. Requires CHROME_CLIENT_ID, CHROME_CLIENT_SECRET,
# CHROME_REFRESH_TOKEN, CHROME_PUBLISHER_ID and CHROME_EXTENSION_ID in the
# environment. See docs/RELEASE.md for how to obtain them.
#
# Endpoints per Google's live v2 discovery document
# (https://chromewebstore.googleapis.com/$discovery/rest?version=v2):
#   upload:       POST /upload/v2/publishers/{id}/items/{id}:upload  -> uploadState
#   status:       GET  /v2/publishers/{id}/items/{id}:fetchStatus   -> lastAsyncUploadState
#   publish:      POST /v2/publishers/{id}/items/{id}:publish       -> state
# "Published" here means accepted into Chrome's review queue (state PENDING_REVIEW),
# same as it always has been — Google still reviews every update by hand.
set -euo pipefail

ZIP_PATH="${1:?usage: publish-chrome.sh <path-to-zip>}"

: "${CHROME_CLIENT_ID:?CHROME_CLIENT_ID is not set}"
: "${CHROME_CLIENT_SECRET:?CHROME_CLIENT_SECRET is not set}"
: "${CHROME_REFRESH_TOKEN:?CHROME_REFRESH_TOKEN is not set}"
: "${CHROME_PUBLISHER_ID:?CHROME_PUBLISHER_ID is not set}"
: "${CHROME_EXTENSION_ID:?CHROME_EXTENSION_ID is not set}"

API_ROOT="https://chromewebstore.googleapis.com"
ITEM="publishers/${CHROME_PUBLISHER_ID}/items/${CHROME_EXTENSION_ID}"

echo "Requesting Chrome Web Store access token..."
TOKEN_RESPONSE=$(curl -sS -X POST https://oauth2.googleapis.com/token \
  -d "client_id=${CHROME_CLIENT_ID}" \
  -d "client_secret=${CHROME_CLIENT_SECRET}" \
  -d "refresh_token=${CHROME_REFRESH_TOKEN}" \
  -d "grant_type=refresh_token")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
if [ -z "$ACCESS_TOKEN" ]; then
  echo "Failed to obtain a Chrome Web Store access token:" >&2
  echo "$TOKEN_RESPONSE" >&2
  exit 1
fi

curl_auth() {
  curl -sS -H "Authorization: Bearer ${ACCESS_TOKEN}" "$@"
}

echo "Uploading ${ZIP_PATH} to Chrome Web Store item ${ITEM}..."
UPLOAD_RESPONSE=$(curl_auth -X POST -T "${ZIP_PATH}" "${API_ROOT}/upload/v2/${ITEM}:upload")
UPLOAD_STATE=$(echo "$UPLOAD_RESPONSE" | jq -r '.uploadState // empty')

if [ "$UPLOAD_STATE" = "IN_PROGRESS" ]; then
  echo "Upload accepted, waiting for processing..."
  for _ in $(seq 1 30); do
    sleep 10
    STATUS_RESPONSE=$(curl_auth "${API_ROOT}/v2/${ITEM}:fetchStatus")
    UPLOAD_STATE=$(echo "$STATUS_RESPONSE" | jq -r '.lastAsyncUploadState // empty')
    case "$UPLOAD_STATE" in
      SUCCEEDED|FAILED|NOT_FOUND)
        break
        ;;
      *)
        echo "  ...upload status: ${UPLOAD_STATE:-unknown}, waiting"
        ;;
    esac
  done
fi

if [ "$UPLOAD_STATE" != "SUCCEEDED" ]; then
  echo "Chrome Web Store upload did not succeed (state: ${UPLOAD_STATE:-unknown}):" >&2
  echo "$UPLOAD_RESPONSE" >&2
  exit 1
fi

echo "Submitting Chrome Web Store item ${ITEM} for publish..."
PUBLISH_RESPONSE=$(curl_auth -X POST -H "Content-Type: application/json" -d '{}' "${API_ROOT}/v2/${ITEM}:publish")
PUBLISH_STATE=$(echo "$PUBLISH_RESPONSE" | jq -r '.state // empty')

case "$PUBLISH_STATE" in
  REJECTED|CANCELLED|"")
    echo "Chrome Web Store publish did not succeed (state: ${PUBLISH_STATE:-unknown}):" >&2
    echo "$PUBLISH_RESPONSE" >&2
    exit 1
    ;;
esac

echo "Chrome Web Store: submitted successfully (state: ${PUBLISH_STATE})."
