#!/usr/bin/env bash
# =============================================================================
# Step 11: Cloud Scheduler. Three schedules start the same Cloud Run Job with a
# different argument (mode). Times are UTC because the sources publish in UTC.
# Run in Cloud Shell from the repository root:   bash infra/scheduler.sh
# Safe to re-run: existing schedules are updated, not duplicated.
#
#   vuln-hourly    15 * * * *   hourly            cvelistV5 delta (changes since 00:00 UTC)
#   vuln-baseline  40 0 * * *   cvelist_baseline  midnight snapshot: catches the last hour
#                                                 of the previous day, which the delta drops
#   vuln-daily     20 6 * * *   daily             NVD + KEV + EPSS (then Dataform, later)
#
# How it works: Scheduler sends an authenticated POST to the Cloud Run Admin API
# "jobs:run" endpoint, as scheduler-sa (which has roles/run.invoker on the job only).
# The body overrides the container arguments for that one execution.
# =============================================================================
set -euo pipefail

PROJECT_ID="vuln-intel-warehouse"
REGION="us-central1"
JOB="vuln-extractor"
SA="scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com"
URI="https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/jobs/${JOB}:run"
gcloud config set project "$PROJECT_ID" >/dev/null

schedule() {  # name, cron, mode, description
  local name=$1 cron=$2 mode=$3 desc=$4
  local body="{\"overrides\":{\"containerOverrides\":[{\"args\":[\"${mode}\"]}]}}"
  local action=create
  gcloud scheduler jobs describe "$name" --location="$REGION" >/dev/null 2>&1 && action=update
  gcloud scheduler jobs "$action" http "$name" \
    --location="$REGION" \
    --schedule="$cron" --time-zone="Etc/UTC" \
    --uri="$URI" --http-method=POST \
    --message-body="$body" --headers="Content-Type=application/json" \
    --oauth-service-account-email="$SA" \
    --oauth-token-scope="https://www.googleapis.com/auth/cloud-platform" \
    --description="$desc" >/dev/null
  echo "  ${name} (${action}d): '${cron}' UTC -> ${mode}"
}

printf '\n\033[1;34m==> Schedules\033[0m\n'
schedule vuln-hourly   "15 * * * *" hourly           "cvelistV5 hourly delta"
schedule vuln-baseline "40 0 * * *" cvelist_baseline "cvelistV5 midnight snapshot (closes the end-of-day gap)"
schedule vuln-daily    "20 6 * * *" daily            "NVD + KEV + EPSS, then transformations"

printf '\n\033[1;34m==> Check\033[0m\n'
gcloud scheduler jobs list --location="$REGION" \
  --format="table(name.basename(), schedule, timeZone, state)"
