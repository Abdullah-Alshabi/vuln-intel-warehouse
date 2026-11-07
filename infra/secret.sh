#!/usr/bin/env bash
# =============================================================================
# Step 6: store the NVD API key in Secret Manager.
# Run in Cloud Shell:   bash infra/secret.sh
# The key is typed hidden, never echoed, and never written to a file.
# =============================================================================
set -euo pipefail
PROJECT_ID="vuln-intel-warehouse"
SECRET="nvd-api-key"
EXTRACTOR_SA="extractor-sa@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud config set project "$PROJECT_ID" >/dev/null

if ! gcloud secrets describe "$SECRET" >/dev/null 2>&1; then
  gcloud secrets create "$SECRET" --replication-policy=automatic >/dev/null
  echo "Created secret $SECRET"
fi

read -r -s -p "Paste the NVD API key (hidden), then press Enter: " KEY; echo
[[ -n "$KEY" ]] || { echo "Empty key, nothing stored."; exit 1; }
printf '%s' "$KEY" | gcloud secrets versions add "$SECRET" --data-file=- >/dev/null
unset KEY
echo "Stored a new version of $SECRET"

gcloud secrets add-iam-policy-binding "$SECRET" \
  --member="serviceAccount:${EXTRACTOR_SA}" --role="roles/secretmanager.secretAccessor" >/dev/null
echo "extractor-sa -> roles/secretmanager.secretAccessor ($SECRET only)"

# Check the key works against NVD without printing it
STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "apiKey: $(gcloud secrets versions access latest --secret="$SECRET")" \
  "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1")
echo "NVD answered HTTP $STATUS with the stored key (200 = key accepted)"
