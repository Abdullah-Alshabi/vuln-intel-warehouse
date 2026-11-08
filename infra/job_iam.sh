#!/usr/bin/env bash
# =============================================================================
# Step 9b: roles that need the Cloud Run Job to exist first.
# Run in Cloud Shell from the repository root:   bash infra/job_iam.sh
# Safe to re-run: bindings are idempotent.
#
#   build-sa     -> roles/run.developer          on the job        (CD: update the image)
#   build-sa     -> roles/iam.serviceAccountUser on extractor-sa   (deploy a job that runs as extractor-sa)
#   scheduler-sa -> roles/run.jobsExecutorWithOverrides on the job (start executions with a mode argument)
#   (roles/run.invoker has run.jobs.run but NOT run.jobs.runWithOverrides, so it is removed)
# =============================================================================
set -euo pipefail

PROJECT_ID="vuln-intel-warehouse"
REGION="us-central1"
JOB="vuln-extractor"
gcloud config set project "$PROJECT_ID" >/dev/null

sa() { echo "$1@${PROJECT_ID}.iam.gserviceaccount.com"; }
say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

say "build-sa can update the job (Continuous Deployment)"
gcloud run jobs add-iam-policy-binding "$JOB" --region="$REGION" \
  --member="serviceAccount:$(sa build-sa)" --role="roles/run.developer" >/dev/null
echo "  build-sa -> roles/run.developer (job ${JOB})"

gcloud iam service-accounts add-iam-policy-binding "$(sa extractor-sa)" \
  --member="serviceAccount:$(sa build-sa)" --role="roles/iam.serviceAccountUser" >/dev/null
echo "  build-sa -> roles/iam.serviceAccountUser (on extractor-sa only)"

say "scheduler-sa can start the job"
gcloud run jobs add-iam-policy-binding "$JOB" --region="$REGION" \
  --member="serviceAccount:$(sa scheduler-sa)" --role="roles/run.jobsExecutorWithOverrides" >/dev/null
echo "  scheduler-sa -> roles/run.jobsExecutorWithOverrides (job ${JOB})"
gcloud run jobs remove-iam-policy-binding "$JOB" --region="$REGION" \
  --member="serviceAccount:$(sa scheduler-sa)" --role="roles/run.invoker" >/dev/null 2>&1 \
  && echo "  scheduler-sa: removed roles/run.invoker (not enough for overrides)" || true

say "Check: job configuration (no secret values are printed)"
gcloud run jobs describe "$JOB" --region="$REGION" --format="yaml(
  spec.template.spec.template.spec.serviceAccountName,
  spec.template.spec.template.spec.timeoutSeconds,
  spec.template.spec.template.spec.maxRetries,
  spec.template.spec.template.spec.containers[0].image,
  spec.template.spec.template.spec.containers[0].resources.limits,
  spec.template.spec.template.spec.containers[0].env)"

say "Check: who can do what on the job"
gcloud run jobs get-iam-policy "$JOB" --region="$REGION" \
  --format="table(bindings.role, bindings.members)"
