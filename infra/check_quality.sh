#!/usr/bin/env bash
# =============================================================================
# Bronze data quality: rule-based checks. Read only. Every row is one rule;
# "failing" must be 0. Exit code 1 if any rule fails (so it can gate a script).
#   bash infra/check_quality.sh
# The same rules move into Dataform assertions, where a failure blocks the report.
# =============================================================================
set -euo pipefail
P="vuln-intel-warehouse"
COHORT_START="2026-10-08"

read -r -d '' SQL <<EOF || true
DECLARE cohort_start TIMESTAMP DEFAULT TIMESTAMP('${COHORT_START}');
DECLARE hour_end TIMESTAMP DEFAULT TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), HOUR);
WITH
kev_obs AS (   -- the latest KEV observation (a new catalog or the same one seen again)
  SELECT batch_id FROM \`$P.ops.ingest_manifest\`
  WHERE source = 'kev' AND status IN ('loaded', 'unchanged') AND batch_id LIKE 'kev:%:%'
  QUALIFY ROW_NUMBER() OVER (ORDER BY finished_at DESC) = 1),
kev_count AS ( -- CISA's own count for that catalog, recorded when it was loaded
  SELECT batch_id, ANY_VALUE(records_seen) published FROM \`$P.ops.ingest_manifest\`
  WHERE source = 'kev' AND status IN ('loaded', 'partial') GROUP BY 1),
units AS (     -- one unit of work: an EPSS day, otherwise a batch or file
  SELECT source, IF(source = 'epss', SPLIT(batch_id, ':')[SAFE_OFFSET(1)], COALESCE(batch_id, file_uri)) unit,
         status, finished_at
  FROM \`$P.ops.ingest_manifest\` WHERE status != 'unchanged'),  -- 'unchanged' never resolves a problem
checks AS (
  -- ---------------------------------------------------------------- cvelist (CVE.org)
  SELECT 'cvelist' src, 'cve_id present, CVE-YYYY-NNNN format' rule,
    COUNTIF(cve_id IS NULL OR NOT REGEXP_CONTAINS(cve_id, r'^CVE-[0-9]{4}-[0-9]{4,}\$')) failing
    FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'cve_id equals cveMetadata.cveId inside the record',
    COUNTIF(cve_id IS DISTINCT FROM JSON_VALUE(record, '\$.cveMetadata.cveId')) FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'state is PUBLISHED or REJECTED',
    COUNTIF(state IS NULL OR state NOT IN ('PUBLISHED', 'REJECTED')) FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'date_published present and inside the cohort',
    COUNTIF(date_published IS NULL OR date_published < cohort_start) FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'date_updated not before date_published (when present)',
    COUNTIF(IFNULL(date_updated < date_published, FALSE)) FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'not published after we observed it (no future dates)',
    COUNTIF(IFNULL(date_published > observed_at, FALSE)) FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'record_hash unique per (cve_id, hash)',
    COUNT(*) - COUNT(DISTINCT CONCAT(cve_id, record_hash)) FROM \`$P.bronze.cvelist_records\`
  -- ---------------------------------------------------------------- NVD
  UNION ALL SELECT 'nvd', 'cve_id equals the id inside the record',
    COUNTIF(cve_id IS DISTINCT FROM JSON_VALUE(record, '\$.id')) FROM \`$P.bronze.nvd_records\`
  UNION ALL SELECT 'nvd', 'vuln_status is a known NVD status',
    COUNTIF(vuln_status IS NULL OR vuln_status NOT IN ('Received', 'Awaiting Analysis', 'Undergoing Analysis',
                                                       'Analyzed', 'Modified', 'Deferred', 'Rejected'))
    FROM \`$P.bronze.nvd_records\`
  UNION ALL SELECT 'nvd', 'last_modified not before published',
    COUNTIF(IFNULL(last_modified < published, FALSE) OR published IS NULL OR last_modified IS NULL)
    FROM \`$P.bronze.nvd_records\`
  UNION ALL SELECT 'nvd', 'every CVSS baseScore present and between 0 and 10',
    (SELECT COUNTIF(IFNULL(SAFE_CAST(JSON_VALUE(m, '\$.cvssData.baseScore') AS FLOAT64) NOT BETWEEN 0 AND 10, TRUE))
     FROM \`$P.bronze.nvd_records\` n,
       UNNEST(ARRAY_CONCAT(IFNULL(JSON_QUERY_ARRAY(n.record, '\$.metrics.cvssMetricV40'), []),
                           IFNULL(JSON_QUERY_ARRAY(n.record, '\$.metrics.cvssMetricV31'), []),
                           IFNULL(JSON_QUERY_ARRAY(n.record, '\$.metrics.cvssMetricV30'), []),
                           IFNULL(JSON_QUERY_ARRAY(n.record, '\$.metrics.cvssMetricV2'), []))) m)
  -- ---------------------------------------------------------------- KEV
  UNION ALL SELECT 'kev', 'cve_id present, CVE format',
    COUNTIF(cve_id IS NULL OR NOT REGEXP_CONTAINS(cve_id, r'^CVE-[0-9]{4}-[0-9]{4,}\$')) FROM \`$P.bronze.kev_records\`
  UNION ALL SELECT 'kev', 'date_added present and not in the future',
    COUNTIF(date_added IS NULL OR date_added > CURRENT_DATE()) FROM \`$P.bronze.kev_records\`
  UNION ALL SELECT 'kev', 'ransomware flag is Known or Unknown (Unknown kept, not false)',
    COUNTIF(known_ransomware_campaign_use IS NULL OR known_ransomware_campaign_use NOT IN ('Known', 'Unknown'))
    FROM \`$P.bronze.kev_records\`
  UNION ALL SELECT 'kev', 'latest observed catalog: stored members = count CISA published',
    (SELECT IFNULL(ABS(COUNTIF(s.cve_id IS NOT NULL) - ANY_VALUE(c.published)), 1)
     FROM kev_obs o LEFT JOIN kev_count c USING (batch_id)
     LEFT JOIN \`$P.bronze.kev_snapshots\` s USING (batch_id))
  -- ---------------------------------------------------------------- EPSS
  UNION ALL SELECT 'epss', 'epss and percentile present and between 0 and 1',
    COUNTIF(IFNULL(epss NOT BETWEEN 0 AND 1, TRUE) OR IFNULL(percentile NOT BETWEEN 0 AND 1, TRUE))
    FROM \`$P.bronze.epss_scores_v2\`
  UNION ALL SELECT 'epss', 'cve_id present, CVE format',
    COUNTIF(cve_id IS NULL OR NOT REGEXP_CONTAINS(cve_id, r'^CVE-[0-9]{4}-[0-9]{4,}\$')) FROM \`$P.bronze.epss_scores_v2\`
  UNION ALL SELECT 'epss', 'one model_version per score_date',
    (SELECT COUNTIF(n > 1) FROM (SELECT score_date, COUNT(DISTINCT model_version) n
                                 FROM \`$P.bronze.epss_scores_v2\` GROUP BY 1))
  UNION ALL SELECT 'epss', 'no missing day from the cohort start to the last score_date',
    (SELECT COUNT(*) FROM UNNEST(GENERATE_DATE_ARRAY(DATE(cohort_start),
        (SELECT MAX(score_date) FROM \`$P.bronze.epss_scores_v2\`))) d
     WHERE d NOT IN (SELECT DISTINCT score_date FROM \`$P.bronze.epss_scores_v2\`))
  UNION ALL SELECT 'epss', 'each file: rows in the table = rows the manifest loaded (both directions)',
    (SELECT COUNTIF(t.n IS DISTINCT FROM m.loaded) FROM
       (SELECT batch_id, COUNT(*) n FROM \`$P.bronze.epss_scores_v2\` GROUP BY 1) t
       FULL OUTER JOIN (SELECT batch_id, SUM(records_new) loaded FROM \`$P.ops.ingest_manifest\`
             WHERE target LIKE '%epss_scores_v2' AND status = 'loaded' GROUP BY 1) m USING (batch_id))
  -- ---------------------------------------------------------------- pipeline health
  UNION ALL SELECT 'ops', 'unresolved work: latest non-unchanged status is failed/partial/conflicts/quarantined',
    (SELECT COUNTIF(status IN ('failed', 'partial', 'conflicts', 'quarantined')) FROM (
       SELECT status FROM units
       QUALIFY ROW_NUMBER() OVER (PARTITION BY source, unit ORDER BY finished_at DESC) = 1))
  UNION ALL SELECT 'ops', 'UTC hours in the last 24 complete hours without a successful hourly run',
    (SELECT 24 - COUNT(DISTINCT TIMESTAMP_TRUNC(started_at, HOUR)) FROM \`$P.ops.ingest_runs\`
     WHERE mode = 'hourly' AND status = 'succeeded'
       AND started_at >= TIMESTAMP_SUB(hour_end, INTERVAL 24 HOUR) AND started_at < hour_end)
)
SELECT src, rule, failing FROM checks ORDER BY src, rule
EOF
bq query --quiet --use_legacy_sql=false --format=json --max_rows=100 "$SQL" > /tmp/dq_result.json
python3 - <<'PY'
import json, sys
rows = json.load(open("/tmp/dq_result.json"))
bad = 0
print(f"{'src':8} {'failing':>8}  result  rule")
for r in rows:
    n = int(r["failing"] or 0); bad += n > 0
    print(f"{r['src']:8} {n:>8}  {'PASS' if n == 0 else 'CHECK'}   {r['rule']}")
print(f"\n{len(rows) - bad}/{len(rows)} rules pass")
open("/tmp/dq_bad", "w").write(str(bad))
PY

echo; echo "Freshness: how old the data is, and when each source was last checked successfully"
bq query --quiet --use_legacy_sql=false "
WITH w AS (SELECT source, last_checked_at FROM \`$P.ops.source_watermarks\`
           QUALIFY ROW_NUMBER() OVER (PARTITION BY source ORDER BY recorded_at DESC) = 1)
SELECT 'cvelist' src, TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), MAX(observed_at), HOUR) data_age_hours, CAST(NULL AS INT64) score_age_days,
  (SELECT TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), last_checked_at, HOUR) FROM w WHERE source = 'cvelist') hours_since_check
  FROM \`$P.bronze.cvelist_records\`
UNION ALL SELECT 'nvd', TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), MAX(observed_at), HOUR), NULL,
  (SELECT TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), last_checked_at, HOUR) FROM w WHERE source = 'nvd') FROM \`$P.bronze.nvd_records\`
UNION ALL SELECT 'kev', TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), MAX(observed_at), HOUR), NULL,
  (SELECT TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), last_checked_at, HOUR) FROM w WHERE source = 'kev') FROM \`$P.bronze.kev_snapshots\`
UNION ALL SELECT 'epss', NULL, DATE_DIFF(CURRENT_DATE(), MAX(score_date), DAY),
  (SELECT TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), last_checked_at, HOUR) FROM w WHERE source = 'epss') FROM \`$P.bronze.epss_scores_v2\`
ORDER BY 1"

[[ "$(cat /tmp/dq_bad)" == "0" ]] || exit 1
