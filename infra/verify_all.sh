#!/usr/bin/env bash
# =============================================================================
# The whole project, checked end to end. Read only on production (SELECT, GET and downloads).
#   bash infra/verify_all.sh              everything except the full cvelist baseline
#   bash infra/verify_all.sh --baseline   also re-reads the latest full baseline (a few hundred MB)
# Do not run it while the daily job is running (06:20-06:40 UTC = 09:20-09:40 Riyadh).
#
#   1. code       offline tests (no cloud)
#   2. infra      deployed extractor = main, schedules, last build
#   3. quality    infra/check_quality.sh (rules on every bronze/silver/gold table)
#   4. warehouse  tests/verify_warehouse.py (manifest -> bronze -> silver -> gold, re-derived)
#   5. raw        tests/verify_raw.py (the stored source files compared value by value with each layer)
#   6. graph      the compiled Dataform dependencies of the publishing gate
# The integration tests (tests/run_integration.sh) create and delete test_ resources, so they are
# NOT part of this read-only check; run them separately before deploying extractor changes.
# =============================================================================
set -uo pipefail
P="vuln-intel-warehouse"; REGION="us-central1"
cd "$(dirname "$0")/.."
FAILED=()
step() { printf '\n\033[1;35m######## %s\033[0m\n' "$1"; }
result() { if [[ "$2" == 0 ]]; then echo "  -> $1: OK"; else echo "  -> $1: FAILED"; FAILED+=("$1"); fi; }

if [[ ! -x /tmp/vuln-venv/bin/python ]]; then
  python3 -m venv /tmp/vuln-venv >/dev/null && /tmp/vuln-venv/bin/pip install -q -r extractor/requirements.txt
fi
PY=/tmp/vuln-venv/bin/python

step "1. Code: offline tests"
python3 tests/test_offline.py | tail -1; result "offline tests" "${PIPESTATUS[0]}"

step "2. Infrastructure"
git fetch -q origin main
SHA="$(gcloud run jobs describe vuln-extractor --region="$REGION" \
        --format='value(spec.template.spec.template.spec.containers[0].env)' | tr ';' '\n' \
        | sed -n "s/.*'name': 'GIT_SHA', 'value': '\([0-9a-f]*\)'.*/\1/p")"
echo "  deployed extractor: ${SHA:-unknown}   main: $(git rev-parse --short origin/main)"
if [[ -n "$SHA" ]] && git cat-file -e "${SHA}^{commit}" 2>/dev/null && git diff --quiet "$SHA" origin/main -- extractor/; then
  result "deployed extractor code = extractor/ on main" 0
else
  result "deployed extractor code = extractor/ on main" 1
fi
gcloud scheduler jobs list --location="$REGION" --format='table(name.basename(), schedule, state)'
N_OK="$(gcloud scheduler jobs list --location="$REGION" --format='value(name.basename(),schedule,state)' \
        | grep -cE 'vuln-hourly\s+15 \* \* \* \*\s+ENABLED|vuln-baseline\s+40 0 \* \* \*\s+ENABLED|vuln-daily\s+20 6 \* \* \*\s+ENABLED')"
result "3 schedules enabled with the expected times" "$([[ "$N_OK" == 3 ]] && echo 0 || echo 1)"
LAST_BUILD="$(gcloud builds list --region="$REGION" --limit=1 --format='value(status)' 2>/dev/null)"
[[ -n "$LAST_BUILD" ]] || LAST_BUILD="$(gcloud builds list --limit=1 --format='value(status)' 2>/dev/null)"
echo "  last Cloud Build: ${LAST_BUILD:-none found}"
result "last Cloud Build succeeded" "$([[ "$LAST_BUILD" == SUCCESS ]] && echo 0 || echo 1)"

step "3. Data quality rules (infra/check_quality.sh)"
bash infra/check_quality.sh; result "check_quality" $?

step "4. Warehouse consistency (tests/verify_warehouse.py)"
$PY tests/verify_warehouse.py; result "warehouse consistency" $?

step "5. Raw files vs every layer (tests/verify_raw.py)"
$PY tests/verify_raw.py "$@"; result "raw vs layers" $?

step "6. Publishing gate in the compiled Dataform graph"
DEPS="$(bash infra/show_deps.sh main cve_current cve_current_candidate cvss_selected)"
echo "$DEPS"
need=("ops.assert_sources_ready" "ops.assert_candidate_matches_scope" "ops.gold_cve_current_candidate_assertions_rowConditions"
      "ops.silver_cve_metrics_assertions_rowConditions")
miss=0; for d in "${need[@]}"; do grep -q "depends on  $d" <<<"$DEPS" || { echo "  missing: $d"; miss=1; }; done
result "gold waits for every check (sources, scope, candidate, silver)" "$miss"

step "Summary"
if [[ ${#FAILED[@]} == 0 ]]; then echo "ALL CHECKS PASSED"; else printf 'FAILED: %s\n' "${FAILED[@]}"; exit 1; fi
