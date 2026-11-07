#!/usr/bin/env bash
set -euo pipefail

# Deploy the API + web UI to Cloud Run. The one place the service settings
# live: run by hand (after `gcloud auth login`), and by
# .github/workflows/deploy-cloud-run.yml with --non-interactive.
#
# Required: GCP_PROJECT_ID. Optional: GCP_REGION, GCP_SERVICE.
# --non-interactive: no prompt, no `gcloud config` change, and no API
#   enabling (the one-time setup in docs/CLOUD_RUN_DEPLOYMENT.md did that).
: "${GCP_PROJECT_ID:?Set GCP_PROJECT_ID to your Google Cloud project ID}"
GCP_REGION="${GCP_REGION:-asia-northeast1}"
GCP_SERVICE="${GCP_SERVICE:-aibom-inspector}"
INTERACTIVE=1
for arg in "$@"; do
  case "$arg" in
    --non-interactive) INTERACTIVE=0 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if ! command -v gcloud >/dev/null 2>&1; then
  echo "Install Google Cloud CLI before deploying." >&2
  exit 1
fi
if [[ ! -f Dockerfile || ! -f pyproject.toml ]]; then
  echo "Run this script from the AIBOM-Inspector repository root." >&2
  exit 1
fi

echo "Project: $GCP_PROJECT_ID"
echo "Region:  $GCP_REGION"
echo "Service: $GCP_SERVICE"
if [[ "$INTERACTIVE" == 1 ]]; then
  echo "This creates billable Google Cloud resources. Review the settings before proceeding."
  read -r -p "Deploy now? [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || exit 0

  gcloud config set project "$GCP_PROJECT_ID"
  gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
fi

gcloud run deploy "$GCP_SERVICE" \
  --project "$GCP_PROJECT_ID" \
  --region "$GCP_REGION" \
  --source . \
  --quiet \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 1 \
  --cpu 1 \
  --memory 1Gi \
  --concurrency 1 \
  --timeout 300 \
  --port 8080 \
  --execution-environment gen2 \
  --set-env-vars "^@^AIBOM_CORS_ORIGINS=https://aibom-inspector.com,https://www.aibom-inspector.com@AIBOM_MAX_CLONE_MB=100@AIBOM_MAX_CLONE_FILES=15000"
# `^@^` makes `@` the separator (gcloud topic escaping): the CORS value itself
# contains a comma, which the default separator would split into a bad entry.

echo "Check the service URL and /api/health endpoint before connecting your domain."
