#!/usr/bin/env bash
# =============================================================================
# Run the tests before pushing extractor changes (pushing deploys to the scheduled job).
# Cloud Shell, from the repository root:   bash tests/run_integration.sh
#
# 1. offline unit tests (no cloud)
# 2. BigQuery/GCS integration tests in throwaway resources:
#      datasets test_bronze, test_ops   +   bucket gs://vuln-intel-warehouse-test
#    Two real EPSS files are copied from the raw bucket (read only). Production tables are
#    never touched. Everything test_* is deleted at the end, even if a test fails.
# =============================================================================
set -euo pipefail
P="vuln-intel-warehouse"
REGION="us-central1"
TEST_BUCKET="gs://${P}-test"
gcloud config set project "$P" >/dev/null

cleanup() {
  echo; echo "==> Cleanup"
  bq rm -r -f -d "${P}:test_bronze" >/dev/null 2>&1 || true
  bq rm -r -f -d "${P}:test_ops" >/dev/null 2>&1 || true
  gcloud storage rm -r "$TEST_BUCKET" >/dev/null 2>&1 || true
  echo "  test datasets and bucket deleted"
}
trap cleanup EXIT

echo "==> Python environment"
python3 -m venv /tmp/vuln-venv >/dev/null
/tmp/vuln-venv/bin/pip install -q -r extractor/requirements.txt

echo; echo "==> 1. Offline unit tests"
python3 tests/test_offline.py

echo; echo "==> 2. Integration tests (throwaway resources)"
cleanup >/dev/null
for ds in test_bronze test_ops; do bq --location="$REGION" mk --dataset "${P}:${ds}" >/dev/null; done
gcloud storage buckets create "$TEST_BUCKET" --location="${REGION^^}" --uniform-bucket-level-access >/dev/null
for f in $(gcloud storage ls "gs://${P}-raw/raw/epss/**" | tail -2); do
  gcloud storage cp "$f" "${TEST_BUCKET}/${f#gs://${P}-raw/}" >/dev/null
done
echo "  copied 2 EPSS files from the raw bucket"

BRONZE_DATASET=test_bronze OPS_DATASET=test_ops BUCKET="${P}-test" GOOGLE_CLOUD_PROJECT="$P" \
  /tmp/vuln-venv/bin/python tests/integration_bq.py
