#!/usr/bin/env bash
# =============================================================================
# Step 7: Artifact Registry repository for the extractor image.
# Run in Cloud Shell:   bash infra/registry.sh
# =============================================================================
set -euo pipefail
PROJECT_ID="vuln-intel-warehouse"
REGION="us-central1"
REPO="vuln-intel"
BUILD_SA="build-sa@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud config set project "$PROJECT_ID" >/dev/null

if gcloud artifacts repositories describe "$REPO" --location="$REGION" >/dev/null 2>&1; then
  echo "Repository $REPO already exists"
else
  gcloud artifacts repositories create "$REPO" --repository-format=docker \
    --location="$REGION" --description="Container images for the vulnerability intelligence extractor"
fi

# Keep storage inside the 0.5 GB free tier: delete images older than 20 days,
# but always keep the 2 most recent versions (keep rules win over delete rules).
POLICY=$(mktemp)
cat > "$POLICY" <<'JSON'
[
  {"name": "delete-old", "action": {"type": "Delete"},
   "condition": {"tagState": "any", "olderThan": "20d"}},
  {"name": "keep-last-2", "action": {"type": "Keep"},
   "mostRecentVersions": {"keepCount": 2}}
]
JSON
gcloud artifacts repositories set-cleanup-policies "$REPO" --location="$REGION" \
  --policy="$POLICY" --no-dry-run >/dev/null
rm -f "$POLICY"
echo "Cleanup policies set: delete-old (20d), keep-last-2"

gcloud artifacts repositories add-iam-policy-binding "$REPO" --location="$REGION" \
  --member="serviceAccount:${BUILD_SA}" --role="roles/artifactregistry.writer" >/dev/null
echo "build-sa -> roles/artifactregistry.writer ($REPO only)"
