#!/usr/bin/env bash
# =============================================================================
# Step 12a: Dataform identity, GitHub token secret, and least-privilege BigQuery roles.
# Run in Cloud Shell from the repository root BEFORE creating the Dataform repository:
#   bash infra/dataform_iam.sh
# Safe to re-run. It asks for the GitHub token (hidden); press Enter to keep the stored one.
#
# Who                              Role                                  On
# Dataform service agent           Secret Manager Secret Accessor        secret dataform-github-token
# Dataform service agent           Service Account Token Creator + User  dataform-sa      (strict act-as)
# extractor-sa                     Service Account User                  dataform-sa      (it starts workflows that run as dataform-sa)
# dataform-sa                      BigQuery Data Viewer                  dataset bronze   (read only)
# dataform-sa                      BigQuery Data Editor                  datasets silver, gold, ops
# dataform-sa                      BigQuery Job User                     project          (kept)
# dataform-sa                      BigQuery Data Editor                  project          REMOVED (too wide)
# =============================================================================
set -euo pipefail
P="vuln-intel-warehouse"
REGION="us-central1"
SECRET="dataform-github-token"
gcloud config set project "$P" >/dev/null
sa() { echo "$1@${P}.iam.gserviceaccount.com"; }
say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

NUM=$(gcloud projects describe "$P" --format='value(projectNumber)')
AGENT="service-${NUM}@gcp-sa-dataform.iam.gserviceaccount.com"

say "Dataform service agent"
gcloud beta services identity create --service=dataform.googleapis.com --project="$P" >/dev/null 2>&1 || true
echo "  $AGENT"

say "GitHub token in Secret Manager (never printed)"
if ! gcloud secrets describe "$SECRET" >/dev/null 2>&1; then
  gcloud secrets create "$SECRET" --replication-policy=automatic >/dev/null
  echo "  created secret $SECRET"
fi
read -r -s -p "  Paste the GitHub token (hidden), or press Enter to keep the stored one: " TOKEN; echo
if [[ -n "$TOKEN" ]]; then
  printf '%s' "$TOKEN" | gcloud secrets versions add "$SECRET" --data-file=- >/dev/null
  echo "  stored a new version of $SECRET"
fi
unset TOKEN
gcloud secrets add-iam-policy-binding "$SECRET" \
  --member="serviceAccount:${AGENT}" --role="roles/secretmanager.secretAccessor" >/dev/null
echo "  Dataform service agent -> secretAccessor ($SECRET only)"

say "Strict act-as: who may run workflows as dataform-sa"
for role in roles/iam.serviceAccountTokenCreator roles/iam.serviceAccountUser; do
  gcloud iam service-accounts add-iam-policy-binding "$(sa dataform-sa)" \
    --member="serviceAccount:${AGENT}" --role="$role" >/dev/null
  echo "  Dataform service agent -> ${role#roles/} (on dataform-sa)"
done
gcloud iam service-accounts add-iam-policy-binding "$(sa dataform-sa)" \
  --member="serviceAccount:$(sa extractor-sa)" --role="roles/iam.serviceAccountUser" >/dev/null
echo "  extractor-sa -> serviceAccountUser (on dataform-sa)"

say "dataform-sa: narrow BigQuery access to the datasets it needs"
bq_grant() {  # role, dataset
  bq query --project_id="$P" --location="$REGION" --use_legacy_sql=false --quiet \
    "GRANT \`$1\` ON SCHEMA \`${P}.$2\` TO \"serviceAccount:$(sa dataform-sa)\"" >/dev/null
  echo "  dataform-sa -> ${1#roles/} ($2)"
}
bq_grant roles/bigquery.dataViewer bronze
for ds in silver gold ops; do bq_grant roles/bigquery.dataEditor "$ds"; done
gcloud projects remove-iam-policy-binding "$P" \
  --member="serviceAccount:$(sa dataform-sa)" --role="roles/bigquery.dataEditor" --condition=None >/dev/null 2>&1 \
  && echo "  dataform-sa: removed project-wide bigquery.dataEditor" || echo "  (project-wide dataEditor was already gone)"

say "Check: dataform-sa project roles (expect only bigquery.jobUser)"
gcloud projects get-iam-policy "$P" --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:$(sa dataform-sa)" --format="value(bindings.role)"
say "Check: who can act as dataform-sa"
gcloud iam service-accounts get-iam-policy "$(sa dataform-sa)" \
  --format="table(bindings.role, bindings.members)"
