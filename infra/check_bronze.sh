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
UNION ALL SELECT 'kev_snapshots', COUNT(*), COUNT(DISTINCT cve_id), COUNT(DISTINCT CONCAT(batch_id, cve_id)) FROM \`$P.bronze.kev_snapshots\`
UNION ALL SELECT 'epss_v2', COUNT(*), COUNT(DISTINCT cve_id), COUNT(DISTINCT CONCAT(cve_id, CAST(score_date AS STRING))) FROM \`$P.bronze.epss_scores_v2\`"

q "1b. cvelist history: extra versions vs CVEs that have more than one version" "
SELECT COUNT(*) - COUNT(DISTINCT cve_id) extra_versions,
  (SELECT COUNT(*) FROM (SELECT cve_id FROM \`$P.bronze.cvelist_records\` GROUP BY 1 HAVING COUNT(*) > 1)) cves_with_2plus_versions,
  (SELECT MAX(n) FROM (SELECT COUNT(*) n FROM \`$P.bronze.cvelist_records\` GROUP BY cve_id)) max_versions_per_cve
FROM \`$P.bronze.cvelist_records\`"

q "2. EPSS per day: whole file each day, plus how many cohort CVEs have a score that day" "
SELECT e.score_date, ANY_VALUE(e.model_version) model, COUNT(*) all_cves,
  COUNTIF(c.cve_id IS NOT NULL) cohort_cves, ROUND(AVG(e.epss), 4) avg_epss_all
FROM \`$P.bronze.epss_scores_v2\` e
LEFT JOIN (SELECT DISTINCT cve_id FROM \`$P.bronze.cvelist_records\`) c USING (cve_id)
GROUP BY 1 ORDER BY 1"

q "3. Coverage: how many cohort CVEs each source knows (the enrichment gap starts here)" "
WITH c AS (SELECT DISTINCT cve_id FROM \`$P.bronze.cvelist_records\`)
SELECT COUNT(*) cohort,
  COUNTIF(cve_id IN (SELECT cve_id FROM \`$P.bronze.nvd_records\`)) in_nvd,
  COUNTIF(cve_id IN (SELECT cve_id FROM \`$P.bronze.epss_scores_v2\`)) in_epss,
  COUNTIF(cve_id IN (SELECT cve_id FROM \`$P.bronze.kev_records\`)) in_kev
FROM c"

q "4. NVD status of the COHORT, latest NVD version per CVE (Deferred in the API = Not Scheduled in the UI)" "
WITH latest AS (
  SELECT n.cve_id, n.vuln_status FROM \`$P.bronze.nvd_records\` n
  WHERE n.cve_id IN (SELECT cve_id FROM \`$P.bronze.cvelist_records\`)
  QUALIFY ROW_NUMBER() OVER (PARTITION BY n.cve_id ORDER BY n.last_modified DESC, n.observed_at DESC) = 1)
SELECT vuln_status, COUNT(*) cves, ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) pct
FROM latest GROUP BY 1 ORDER BY 2 DESC"

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

q "9. CVEs seen by all four sources; CVSS 3.1 is the Primary score authored by NVD itself" "
WITH nvd AS (
  SELECT cve_id, vuln_status, record FROM \`$P.bronze.nvd_records\`
  QUALIFY ROW_NUMBER() OVER (PARTITION BY cve_id ORDER BY last_modified DESC, observed_at DESC) = 1),
nvd_score AS (
  SELECT cve_id, ANY_VALUE(JSON_VALUE(m, '\$.cvssData.baseScore')) nvd_cvss31
  FROM nvd, UNNEST(JSON_QUERY_ARRAY(record, '\$.metrics.cvssMetricV31')) m
  WHERE JSON_VALUE(m, '\$.type') = 'Primary' AND JSON_VALUE(m, '\$.source') = 'nvd@nist.gov'
  GROUP BY cve_id),
epss AS (
  SELECT cve_id, epss, score_date FROM \`$P.bronze.epss_scores_v2\`
  QUALIFY ROW_NUMBER() OVER (PARTITION BY cve_id ORDER BY score_date DESC) = 1)
SELECT c.cve_id, c.state, c.date_published, n.vuln_status, s.nvd_cvss31, e.epss, e.score_date, k.date_added kev_added
FROM (SELECT * FROM \`$P.bronze.cvelist_records\`
      QUALIFY ROW_NUMBER() OVER (PARTITION BY cve_id ORDER BY date_updated DESC, observed_at DESC) = 1) c
JOIN nvd n USING (cve_id)
LEFT JOIN nvd_score s USING (cve_id)
JOIN epss e USING (cve_id)
JOIN \`$P.bronze.kev_records\` k USING (cve_id)
ORDER BY c.date_published
LIMIT 5"

printf '\n\033[1;34m==> 10. Raw layer: bytes per source in the bucket\033[0m\n'
for s in cvelist nvd kev epss; do
  printf '  %-8s %s\n' "$s" "$(gcloud storage du -s "gs://${P}-raw/raw/${s}/" 2>/dev/null | awk '{printf "%.1f MB", $1/1e6}')"
done
echo "  locks:   $(gcloud storage ls "gs://${P}-raw/locks/" 2>/dev/null | wc -l) (expect 0 when nothing is running)"
