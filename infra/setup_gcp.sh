#!/usr/bin/env bash
# =============================================================================
# Vulnerability Intelligence Warehouse: Google Cloud setup.
# Every step was first done in the Cloud Console; the commands below are the
# console's "Equivalent code", kept here so the environment can be rebuilt.
# Run in Cloud Shell:   bash infra/setup_gcp.sh
# =============================================================================
set -euo pipefail

PROJECT_ID="vuln-intel-warehouse"
REGION="us-central1"
BUCKET="vuln-intel-warehouse-raw"

gcloud config set project "$PROJECT_ID"

# --- 1. Project and billing (done in the console) ------------------------------
# Project "Vuln Intel Warehouse" (ID vuln-intel-warehouse), No organization,
# linked to the free-trial billing account.
# Budget "vuln-intel-budget": 20 USD/month, this project only, all services,
# savings/credits NOT applied (so alerts fire on real cost during the trial),
# email alerts at 50%, 90%, 100% of actual spend.

# --- 2. APIs ------------------------------------------------------------------
gcloud services enable \
  run.googleapis.com cloudscheduler.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com secretmanager.googleapis.com dataform.googleapis.com \
  bigquery.googleapis.com storage.googleapis.com iamcredentials.googleapis.com \
  monitoring.googleapis.com logging.googleapis.com

# --- 3. Raw layer bucket ------------------------------------------------------
gcloud storage buckets create "gs://${BUCKET}" \
  --default-storage-class=STANDARD \
  --location="${REGION^^}" \
  --uniform-bucket-level-access \
  --public-access-prevention
