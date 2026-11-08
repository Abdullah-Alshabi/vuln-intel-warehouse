#!/usr/bin/env bash
# =============================================================================
# Bronze health check: run after any load, before trusting the data.
# Run in Cloud Shell from the repository root:   bash infra/check_bronze.sh
# Read-only: it only runs SELECT queries and lists the bucket.
# =============================================================================
set -euo pipefail
P="vuln-intel-warehouse"
q() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; bq query --quiet --use_legacy_sql=false --max_rows=100 "$2"; }

q "1. Rows per table. rows = distinct_versions means no duplicate (cve, hash)" "
SELECT 'cvelist' t, COUNT(*) rows_, COUNT(DISTINCT cve_id) cves, COUNT(DISTINCT CONCAT(cve_id, record_hash)) distinct_versions FROM \`$P.bronze.cvelist_records\`
UNION ALL SELECT 'nvd', COUNT(*), COUNT(DISTINCT cve_id), COUNT(DISTINCT CONCAT(cve_id, record_hash)) FROM \`$P.bronze.nvd_records\`
UNION ALL SELECT 'kev', COUNT(*), COUNT(DISTINCT cve_id), COUNT(DISTINCT CONCAT(cve_id, record_hash)) FROM \`$P.bronze.kev_records\`
UNION ALL SELECT 'epss', COUNT(*), COUNT(DISTINCT cve_id), COUNT(DISTINCT CONCAT(cve_id, CAST(score_date AS STRING))) FROM \`$P.bronze.epss_scores\`"

q "2. EPSS per day: expect ~31 days, count growing as the cohort grows" "
SELECT score_date, ANY_VALUE(model_version) model, COUNT(*) cves, ROUND(AVG(epss), 4) avg_epss
FROM \`$P.bronze.epss_scores\` GROUP BY 1 ORDER BY 1"

q "3. Coverage: how many cohort CVEs each source knows (the enrichment gap starts here)" "
WITH c AS (SELECT DISTINCT cve_id FROM \`$P.bronze.cvelist_records\`)
SELECT COUNT(*) cohort,
  COUNTIF(cve_id IN (SELECT cve_id FROM \`$P.bronze.nvd_records\`)) in_nvd,
  COUNTIF(cve_id IN (SELECT cve_id FROM \`$P.bronze.epss_scores\`)) in_epss,
  COUNTIF(cve_id IN (SELECT cve_id FROM \`$P.bronze.kev_records\`)) in_kev
FROM c"

q "4. NVD status of the cohort (Deferred in the API = Not Scheduled in the UI)" "
SELECT vuln_status, COUNT(DISTINCT cve_id) cves FROM \`$P.bronze.nvd_records\` GROUP BY 1 ORDER BY 2 DESC"

q "5. NVD rows outside the cohort (expected: a few, from the 2-day margin; not thousands)" "
SELECT COUNT(DISTINCT cve_id) nvd_not_in_cvelist, MIN(published) min_pub, MAX(published) max_pub
FROM \`$P.bronze.nvd_records\`
WHERE cve_id NOT IN (SELECT cve_id FROM \`$P.bronze.cvelist_records\`)"

q "6. KEV: one catalog, ransomware flag kept as Known/Unknown" "
SELECT catalog_version, known_ransomware_campaign_use, COUNT(*) n,
  COUNTIF(date_added >= '2026-10-08') added_since_cohort_start
FROM \`$P.bronze.kev_records\` GROUP BY 1, 2 ORDER BY 1, 2"

q "7. Watermarks (latest row per source is the current one)" "
SELECT source, watermark, last_checked_at, recorded_at
FROM \`$P.ops.source_watermarks\`
QUALIFY ROW_NUMBER() OVER (PARTITION BY source ORDER BY recorded_at DESC) = 1"

q "8. Manifest: any status other than loaded/unchanged needs a look" "
SELECT source, mode, status, COUNT(*) files, SUM(records_new) records_new, MAX(finished_at) last
FROM \`$P.ops.ingest_manifest\` GROUP BY 1, 2, 3 ORDER BY 1, 2, 3"

q "9. One CVE seen by all four sources (sanity check of the joins we will build)" "
SELECT c.cve_id, c.state, c.date_published, n.vuln_status,
  JSON_VALUE(n.record, '\$.metrics.cvssMetricV31[0].cvssData.baseScore') nvd_cvss31,
  e.epss, k.date_added kev_added
FROM \`$P.bronze.cvelist_records\` c
JOIN \`$P.bronze.nvd_records\` n USING (cve_id)
JOIN \`$P.bronze.epss_scores\` e USING (cve_id)
JOIN \`$P.bronze.kev_records\` k USING (cve_id)
QUALIFY ROW_NUMBER() OVER (PARTITION BY c.cve_id ORDER BY e.score_date DESC) = 1
LIMIT 5"

printf '\n\033[1;34m==> 10. Raw layer: bytes per source in the bucket\033[0m\n'
for s in cvelist nvd kev epss; do
  printf '  %-8s %s\n' "$s" "$(gcloud storage du -s "gs://${P}-raw/raw/${s}/" 2>/dev/null | awk '{printf "%.1f MB", $1/1e6}')"
done
echo "  locks:   $(gcloud storage ls "gs://${P}-raw/locks/" 2>/dev/null | wc -l) (expect 0 when nothing is running)"
