#!/usr/bin/env bash
# =============================================================================
# Compile and run the Dataform workflow from any Git branch, before merging it.
# Runs as dataform-sa (same identity as production). Cloud Shell:
#   bash infra/dataform_run.sh <branch> [tag]      e.g.  bash infra/dataform_run.sh step2/silver
# With a tag, only actions with that tag run; without, every action runs.
# Prints compilation errors, then each action's final state.
# =============================================================================
set -euo pipefail
P="vuln-intel-warehouse"; REGION="us-central1"; REPO="vuln-intel-dataform"
BRANCH="${1:?usage: bash infra/dataform_run.sh <branch> [tag]}"; TAG="${2:-}"
SA="dataform-sa@${P}.iam.gserviceaccount.com"
API="https://dataform.googleapis.com/v1beta1/projects/${P}/locations/${REGION}/repositories/${REPO}"
TOKEN="$(gcloud auth print-access-token)"
call() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" "$@"; }

echo "==> Compiling branch ${BRANCH}"
COMP="$(call -X POST "${API}/compilationResults" -d "{\"gitCommitish\": \"${BRANCH}\"}")"
python3 - "$COMP" <<'PY'
import json, sys
c = json.loads(sys.argv[1])
if "error" in c:
    print("  API error:", c["error"].get("message")); sys.exit(1)
errs = c.get("compilationErrors", [])
print("  commit:", c.get("resolvedGitCommitSha"))
for e in errs:
    print("  ERROR in", e.get("path"), "->", e.get("message"))
sys.exit(1 if errs else 0)
PY
NAME="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["name"])' "$COMP")"

echo "==> Running as ${SA}${TAG:+ (tag: $TAG)}"
CFG="{\"serviceAccount\": \"${SA}\"${TAG:+, \"includedTags\": [\"$TAG\"]}}"
INV="$(call -X POST "${API}/workflowInvocations" -d "{\"compilationResult\": \"${NAME}\", \"invocationConfig\": ${CFG}}")"
INV_NAME="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d.get("name") or sys.exit("  refused: " + json.dumps(d)))' "$INV")"
for _ in $(seq 1 90); do
  sleep 10
  STATE="$(call "https://dataform.googleapis.com/v1beta1/${INV_NAME}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state"))')"
  [[ "$STATE" == "RUNNING" ]] || break
done
echo "  workflow: ${STATE}"
call "https://dataform.googleapis.com/v1beta1/${INV_NAME}:query" | python3 -c '
import json, sys
for a in json.load(sys.stdin).get("workflowInvocationActions", []):
    t = a.get("target", {})
    print(f"  {a.get(\"state\", \"?\"):10} {t.get(\"schema\")}.{t.get(\"name\")}", ("-> " + a["failureReason"][:200]) if a.get("failureReason") else "")
'
[[ "$STATE" == "SUCCEEDED" ]]
