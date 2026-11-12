#!/usr/bin/env bash
# =============================================================================
# Show the COMPILED Dataform graph (read only: compiles, runs nothing).
#   bash infra/show_deps.sh [branch] [action...]
#   bash infra/show_deps.sh main                       dependencies of the gold actions
#   bash infra/show_deps.sh main cve_current_candidate  dependencies of one action
# For each action: its dependencies as Dataform compiled them. For assertions whose name contains
# "_assertions_" (the automatic checks), the compiled SQL is printed too.
# =============================================================================
set -euo pipefail
P="vuln-intel-warehouse"; REGION="us-central1"; REPO="vuln-intel-dataform"
BRANCH="${1:-main}"; shift || true
NAMES="${*:-cve_current_candidate cve_current gold_cve_current_candidate_assertions_rowConditions}"
API="https://dataform.googleapis.com/v1beta1/projects/${P}/locations/${REGION}/repositories/${REPO}"
TOKEN="$(gcloud auth print-access-token)"
call() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" "$@"; }

COMP="$(call -X POST "${API}/compilationResults" -d "{\"gitCommitish\": \"${BRANCH}\"}")"
NAME="$(python3 -c 'import json,sys; c=json.loads(sys.argv[1]); print(c.get("name") or sys.exit("API error: " + json.dumps(c)))' "$COMP")"
call "https://dataform.googleapis.com/v1beta1/${NAME}:query?pageSize=1000" | python3 -c '
import json, sys
wanted = sys.argv[1].split()
for a in json.load(sys.stdin).get("compilationResultActions", []):
    t = a.get("target", {})
    if t.get("name") not in wanted:
        continue
    body = a.get("relation") or a.get("assertion") or {}
    print("\n== %s.%s" % (t.get("schema"), t.get("name")))
    for d in body.get("dependencyTargets", []):
        print("   depends on  %s.%s" % (d.get("schema"), d.get("name")))
    if "_assertions_" in t.get("name", "") and "assertion" in a:
        print("   compiled SQL:\n" + a["assertion"].get("selectQuery", ""))
' "$NAMES"
