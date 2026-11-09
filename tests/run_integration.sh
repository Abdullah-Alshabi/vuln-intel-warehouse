#!/usr/bin/env bash
# =============================================================================
# Run the tests before pushing extractor changes (pushing deploys to the scheduled job).
# Cloud Shell, from the repository root:   bash tests/run_integration.sh
#
# 1. offline unit tests (no cloud)
# 2. BigQuery/GCS integration tests in throwaway resources:
#      datasets test_bronze_<id>, test_ops_<id>   +   bucket gs://vuln-intel-warehouse-test-<id>
#    Two real EPSS files are copied from the raw bucket (read only). Production tables are
#    never touched. Only this run's resources are deleted at the end, even if a test fails.
# =============================================================================
set -euo pipefail
P="vuln-intel-warehouse"
REGION="us-central1"
SFX="$(date +%s)$RANDOM"                  # unique per run: only this run's resources are touched
DS_BRONZE="test_bronze_${SFX}"
DS_OPS="test_ops_${SFX}"
TEST_BUCKET="gs://${P}-test-${SFX}"
gcloud config set project "$P" >/dev/null

cleanup() {
  echo; echo "==> Cleanup"
  bq rm -r -f -d "${P}:${DS_BRONZE}" >/dev/null 2>&1 || true
  bq rm -r -f -d "${P}:${DS_OPS}" >/dev/null 2>&1 || true
  gcloud storage rm -r "$TEST_BUCKET" >/dev/null 2>&1 || true
  echo "  deleted ${DS_BRONZE}, ${DS_OPS}, ${TEST_BUCKET}"
}
trap cleanup EXIT

echo "==> Python environment"
python3 -m venv /tmp/vuln-venv >/dev/null
/tmp/vuln-venv/bin/pip install -q -r extractor/requirements.txt

echo; echo "==> 1. Offline unit tests"
python3 tests/test_offline.py

echo; echo "==> 2. Integration tests (throwaway resources)"
for ds in "$DS_BRONZE" "$DS_OPS"; do bq --location="$REGION" mk --dataset "${P}:${ds}" >/dev/null; done
gcloud storage buckets create "$TEST_BUCKET" --location="${REGION^^}" --uniform-bucket-level-access >/dev/null
for f in $(gcloud storage ls "gs://${P}-raw/raw/epss/**" | tail -2); do
  gcloud storage cp "$f" "${TEST_BUCKET}/${f#gs://${P}-raw/}" >/dev/null
done
echo "  copied 2 EPSS files from the raw bucket"

BRONZE_DATASET="$DS_BRONZE" OPS_DATASET="$DS_OPS" BUCKET="${TEST_BUCKET#gs://}" GOOGLE_CLOUD_PROJECT="$P" \
  /tmp/vuln-venv/bin/python tests/integration_bq.py
