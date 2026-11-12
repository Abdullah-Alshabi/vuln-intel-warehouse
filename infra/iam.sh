#!/usr/bin/env bash
# =============================================================================
# Step 5: service accounts and least-privilege roles.
# Run in Cloud Shell from the repository root:   bash infra/iam.sh
# Safe to re-run: existing accounts are skipped, bindings are idempotent.
#
# Roles that need a resource that does not exist yet are granted later:
#   extractor-sa -> Secret Accessor on the NVD key        (step 6)
#   build-sa     -> Artifact Registry Writer on the repo  (step 7)
#   scheduler-sa -> Cloud Run Invoker on the job          (after the job exists)
#   build-sa     -> Cloud Run Developer + Service Account User on extractor-sa (CD)
# =============================================================================
set -euo pipefail

PROJECT_ID="vuln-intel-warehouse"
REGION="us-central1"
BUCKET="vuln-intel-warehouse-raw"
gcloud config set project "$PROJECT_ID" >/dev/null

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
sa() { echo "$1@${PROJECT_ID}.iam.gserviceaccount.com"; }

# --- 5a. Service accounts -----------------------------------------------------
say "5a. Service accounts"
create_sa() {  # name, description
  if gcloud iam service-accounts describe "$(sa "$1")" >/dev/null 2>&1; then
    echo "  $1 already exists"
  else
    gcloud iam service-accounts create "$1" --display-name="$1" --description="$2" >/dev/null
    echo "  $1 created"
  fi
}
create_sa extractor-sa "Cloud Run extractor: pulls sources, loads bronze, starts Dataform"
create_sa dataform-sa  "Dataform: builds silver and gold in BigQuery"
create_sa scheduler-sa "Cloud Scheduler: starts the extractor job"
create_sa build-sa     "Cloud Build: builds and deploys the extractor image"
sleep 15  # new service accounts take a few seconds to become visible to IAM

# --- 5a. Project-level roles (the ones that cannot be narrowed further) -------
say "5a. Project-level roles"
grant_project() {  # account, role
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$(sa "$1")" --role="$2" --condition=None >/dev/null
  echo "  $1 -> $2 (project)"
}
grant_project extractor-sa roles/bigquery.jobUser
grant_project extractor-sa roles/dataform.editor
# dataform-sa gets NO project-wide dataEditor: its dataset-level roles are set by infra/dataform_iam.sh
grant_project dataform-sa  roles/bigquery.jobUser
grant_project build-sa     roles/logging.logWriter

# --- 5b. Resource-level roles (least privilege) -------------------------------
say "5b. Bucket: extractor-sa can read and write objects in the raw bucket only"
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:$(sa extractor-sa)" --role="roles/storage.objectUser" >/dev/null
echo "  extractor-sa -> roles/storage.objectUser (gs://${BUCKET})"

say "5b. Datasets: extractor-sa can edit bronze and ops only"
for ds in bronze ops; do
  bq query --project_id="$PROJECT_ID" --location="$REGION" --use_legacy_sql=false --quiet \
    "GRANT \`roles/bigquery.dataEditor\` ON SCHEMA \`${PROJECT_ID}.${ds}\`
     TO \"serviceAccount:$(sa extractor-sa)\"" >/dev/null
  echo "  extractor-sa -> roles/bigquery.dataEditor (${ds})"
done

# --- Check ---------------------------------------------------------------------
say "Project-level roles now:"
gcloud projects get-iam-policy "$PROJECT_ID" --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount AND bindings.members:${PROJECT_ID}.iam" \
  --format="table(bindings.members, bindings.role)"
