#!/usr/bin/env bash
# =============================================================================
# Bronze data quality: rule-based checks. Read only. Every row is one rule;
# "failing" must be 0 unless the note says otherwise.
#   bash infra/check_quality.sh
# The same rules move into Dataform assertions, where a failure blocks the report.
# =============================================================================
set -euo pipefail
P="vuln-intel-warehouse"
bq query --quiet --use_legacy_sql=false --max_rows=100 "
DECLARE cohort_start TIMESTAMP DEFAULT TIMESTAMP('2026-10-08');
WITH checks AS (
  -- ---------------------------------------------------------------- cvelist (CVE.org)
  SELECT 'cvelist' src, 'cve_id has the CVE-YYYY-NNNN format' rule,
    COUNTIF(NOT REGEXP_CONTAINS(cve_id, r'^CVE-[0-9]{4}-[0-9]{4,}\$')) failing FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'cve_id equals cveMetadata.cveId inside the record',
    COUNTIF(cve_id != JSON_VALUE(record, '\$.cveMetadata.cveId')) FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'state is PUBLISHED or REJECTED',
    COUNTIF(state NOT IN ('PUBLISHED', 'REJECTED') OR state IS NULL) FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'date_published is inside the cohort',
    COUNTIF(date_published IS NULL OR date_published < cohort_start) FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'date_updated is not before date_published',
    COUNTIF(date_updated < date_published) FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'not published after we observed it (no future dates)',
    COUNTIF(date_published > observed_at) FROM \`$P.bronze.cvelist_records\`
  UNION ALL SELECT 'cvelist', 'record_hash unique per (cve_id, hash)',
    COUNT(*) - COUNT(DISTINCT CONCAT(cve_id, record_hash)) FROM \`$P.bronze.cvelist_records\`
  -- ---------------------------------------------------------------- NVD
  UNION ALL SELECT 'nvd', 'cve_id equals the id inside the record',
    COUNTIF(cve_id != JSON_VALUE(record, '\$.id')) FROM \`$P.bronze.nvd_records\`
  UNION ALL SELECT 'nvd', 'vuln_status is a known NVD status',
    COUNTIF(vuln_status NOT IN ('Received', 'Awaiting Analysis', 'Undergoing Analysis', 'Analyzed',
                                'Modified', 'Deferred', 'Rejected') OR vuln_status IS NULL)
    FROM \`$P.bronze.nvd_records\`
  UNION ALL SELECT 'nvd', 'last_modified is not before published',
    COUNTIF(last_modified < published) FROM \`$P.bronze.nvd_records\`
  UNION ALL SELECT 'nvd', 'every CVSS baseScore is between 0 and 10',
    (SELECT COUNTIF(SAFE_CAST(JSON_VALUE(m, '\$.cvssData.baseScore') AS FLOAT64) NOT BETWEEN 0 AND 10)
     FROM \`$P.bronze.nvd_records\` n,
       UNNEST(ARRAY_CONCAT(JSON_QUERY_ARRAY(n.record, '\$.metrics.cvssMetricV40'),
                           JSON_QUERY_ARRAY(n.record, '\$.metrics.cvssMetricV31'),
                           JSON_QUERY_ARRAY(n.record, '\$.metrics.cvssMetricV30'),
                           JSON_QUERY_ARRAY(n.record, '\$.metrics.cvssMetricV2'))) m)
  -- ---------------------------------------------------------------- KEV
  UNION ALL SELECT 'kev', 'cve_id has the CVE format',
    COUNTIF(NOT REGEXP_CONTAINS(cve_id, r'^CVE-[0-9]{4}-[0-9]{4,}\$')) FROM \`$P.bronze.kev_records\`
  UNION ALL SELECT 'kev', 'date_added present and not in the future',
    COUNTIF(date_added IS NULL OR date_added > CURRENT_DATE()) FROM \`$P.bronze.kev_records\`
  UNION ALL SELECT 'kev', 'ransomware flag is Known or Unknown (Unknown kept, not false)',
    COUNTIF(known_ransomware_campaign_use NOT IN ('Known', 'Unknown') OR known_ransomware_campaign_use IS NULL)
    FROM \`$P.bronze.kev_records\`
  UNION ALL SELECT 'kev', 'latest snapshot size equals the catalog count CISA published',
    (SELECT ABS(COUNT(*) - ANY_VALUE(m.records_seen)) FROM \`$P.bronze.kev_snapshots\` s
     JOIN (SELECT batch_id, records_seen FROM \`$P.ops.ingest_manifest\`
           WHERE source = 'kev' AND status = 'loaded' AND batch_id LIKE 'kev:%:%'
           QUALIFY ROW_NUMBER() OVER (ORDER BY finished_at DESC) = 1) m USING (batch_id))
  -- ---------------------------------------------------------------- EPSS
  UNION ALL SELECT 'epss', 'epss and percentile between 0 and 1',
    COUNTIF(epss NOT BETWEEN 0 AND 1 OR percentile NOT BETWEEN 0 AND 1 OR epss IS NULL OR percentile IS NULL)
    FROM \`$P.bronze.epss_scores_v2\`
  UNION ALL SELECT 'epss', 'cve_id has the CVE format',
    COUNTIF(NOT REGEXP_CONTAINS(cve_id, r'^CVE-[0-9]{4}-[0-9]{4,}\$')) FROM \`$P.bronze.epss_scores_v2\`
  UNION ALL SELECT 'epss', 'one model_version per score_date',
    (SELECT COUNTIF(n > 1) FROM (SELECT score_date, COUNT(DISTINCT model_version) n
                                 FROM \`$P.bronze.epss_scores_v2\` GROUP BY 1))
  UNION ALL SELECT 'epss', 'no missing day between the first and the last score_date',
    (SELECT DATE_DIFF(MAX(score_date), MIN(score_date), DAY) + 1 - COUNT(DISTINCT score_date)
     FROM \`$P.bronze.epss_scores_v2\`)
  UNION ALL SELECT 'epss', 'rows per file in the table = rows the manifest says were loaded',
    (SELECT COUNTIF(t.n != m.loaded) FROM
       (SELECT batch_id, COUNT(*) n FROM \`$P.bronze.epss_scores_v2\` GROUP BY 1) t
       JOIN (SELECT batch_id, SUM(records_new) loaded FROM \`$P.ops.ingest_manifest\`
             WHERE target LIKE '%epss_scores_v2' GROUP BY 1) m USING (batch_id))
  -- ---------------------------------------------------------------- pipeline health
  UNION ALL SELECT 'ops', 'files failed, quarantined, partial or in conflict',
    COUNTIF(status IN ('failed', 'quarantined', 'partial', 'conflicts')) FROM \`$P.ops.ingest_manifest\`
  UNION ALL SELECT 'ops', 'failed runs in the last 24 hours',
    COUNTIF(status = 'failed' AND started_at > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR))
    FROM \`$P.ops.ingest_runs\`
  UNION ALL SELECT 'ops', 'hourly runs missing in the last 24 hours (expect 0-1)',
    24 - (SELECT COUNT(*) FROM \`$P.ops.ingest_runs\` WHERE mode = 'hourly' AND status = 'succeeded'
          AND started_at > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR))
)
SELECT src, rule, failing, IF(failing = 0, 'PASS', 'CHECK') result FROM checks ORDER BY src, rule"

echo; echo "Freshness: hours since each source last brought new data"
bq query --quiet --use_legacy_sql=false "
SELECT 'cvelist' src, TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), MAX(observed_at), HOUR) hours_old FROM \`$P.bronze.cvelist_records\`
UNION ALL SELECT 'nvd', TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), MAX(observed_at), HOUR) FROM \`$P.bronze.nvd_records\`
UNION ALL SELECT 'kev', TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), MAX(observed_at), HOUR) FROM \`$P.bronze.kev_snapshots\`
UNION ALL SELECT 'epss', DATE_DIFF(CURRENT_DATE(), MAX(score_date), DAY) * 24 FROM \`$P.bronze.epss_scores_v2\`
ORDER BY 1"
