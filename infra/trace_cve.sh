#!/usr/bin/env bash
# =============================================================================
# Follow one CVE through the layers: bronze (every stored version) -> silver (what was chosen).
#   bash infra/trace_cve.sh                 picks a CVE that is in KEV and has several versions
#   bash infra/trace_cve.sh CVE-2026-12345  traces that CVE
# Read only.
# =============================================================================
set -euo pipefail
P="vuln-intel-warehouse"
q() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; bq query --quiet --use_legacy_sql=false --parameter="cve::${CVE}" "$2"; }

CVE="${1:-}"
if [[ -z "$CVE" ]]; then
  CVE="$(bq query --quiet --use_legacy_sql=false --format=csv "
    SELECT c.cve_id FROM \`$P.silver.cve_latest\` c
    LEFT JOIN \`$P.silver.kev_current\` k USING (cve_id)
    LEFT JOIN \`$P.silver.epss_latest\` e USING (cve_id)
    WHERE c.state = 'PUBLISHED'
    ORDER BY k.cve_id IS NOT NULL DESC, c.versions_stored DESC, e.epss DESC LIMIT 1" | tail -1)"
fi
echo "Tracing ${CVE}"

q "BRONZE cvelist: every version we stored (newest first)" "
SELECT state, date_published, date_updated, SUBSTR(record_hash, 1, 12) hash12, batch_id, observed_at
FROM \`$P.bronze.cvelist_records\` WHERE cve_id = @cve
ORDER BY COALESCE(date_updated, date_published) DESC, observed_at DESC, record_hash DESC   -- same order as silver"

q "SILVER cve_latest: the version chosen (its hash must be the first one above)" "
SELECT state, date_published, date_updated, assigner, first_listed_vendor, first_listed_product, versions_stored,
  SUBSTR(record_hash, 1, 12) hash12, SUBSTR(description, 1, 120) description
FROM \`$P.silver.cve_latest\` WHERE cve_id = @cve"

q "BRONZE nvd: every version we stored" "
SELECT vuln_status, last_modified, SUBSTR(record_hash, 1, 12) hash12, observed_at
FROM \`$P.bronze.nvd_records\` WHERE cve_id = @cve ORDER BY last_modified DESC, observed_at DESC, record_hash DESC"

q "SILVER nvd_latest" "
SELECT nvd_status, nvd_last_modified, SUBSTR(record_hash, 1, 12) hash12 FROM \`$P.silver.nvd_latest\` WHERE cve_id = @cve"

q "SILVER kev_current (no row = not in the latest valid KEV catalog)" "
SELECT catalog_version, kev_checked_at, date_added, ransomware_use FROM \`$P.silver.kev_current\` WHERE cve_id = @cve"

q "BRONZE epss: last 5 days we hold for this CVE" "
SELECT score_date, epss, percentile, model_version FROM \`$P.bronze.epss_scores_v2\`
WHERE cve_id = @cve ORDER BY score_date DESC LIMIT 5"

q "SILVER epss_latest: the score used (latest complete day only)" "
SELECT epss_score_date, epss, ROUND(epss * 100, 2) epss_pct, epss_percentile, epss_model_version
FROM \`$P.silver.epss_latest\` WHERE cve_id = @cve"

q "SILVER cve_metrics: CVSS scores of the chosen CVE.org and NVD versions only" "
SELECT m.ingestion_source, m.provider_role, m.provider_label, m.nvd_type, m.cvss_version, m.base_score, m.vector
FROM \`$P.silver.cve_metrics\` m
WHERE m.cve_id = @cve AND m.record_hash IN (
  SELECT record_hash FROM \`$P.silver.cve_latest\` WHERE cve_id = @cve
  UNION ALL SELECT record_hash FROM \`$P.silver.nvd_latest\` WHERE cve_id = @cve)
ORDER BY m.cvss_version DESC, m.ingestion_source, m.provider_role"
