#!/usr/bin/env bash
# =============================================================================
# Read-only checks for the audit fixes (F2, F4, F5, F6) on PRODUCTION data, before merging.
#   bash infra/verify_audit.sh            (only SELECT queries; changes nothing)
# =============================================================================
set -euo pipefail
P="vuln-intel-warehouse"
q() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; bq query --quiet --use_legacy_sql=false --max_rows=50 "$2"; }

q "F4: old vs new EPSS completeness on every stored day (expected: 0 days where they differ)" "
WITH m AS (
  SELECT SAFE.PARSE_DATE('%Y-%m-%d', SPLIT(batch_id, ':')[SAFE_OFFSET(1)]) AS score_date,
    COUNTIF(status = 'loaded') ok_loads, COUNTIF(status = 'conflicts') conflict_rows,
    SUM(IF(status = 'loaded', records_new, 0)) old_rows,
    MAX(IF(status = 'loaded', records_in_scope, NULL)) new_rows
  FROM \`$P.ops.ingest_manifest\` WHERE target = '$P.bronze.epss_scores_v2' GROUP BY 1),
t AS (SELECT score_date, COUNT(*) table_rows FROM \`$P.bronze.epss_scores_v2\` GROUP BY 1)
SELECT COUNT(*) days,
  COUNTIF(ok_loads > 0 AND conflict_rows = 0 AND table_rows > 0 AND table_rows = old_rows) complete_old,
  COUNTIF(ok_loads > 0 AND conflict_rows = 0 AND table_rows > 0 AND table_rows = new_rows) complete_new,
  COUNTIF((table_rows = old_rows) IS DISTINCT FROM (table_rows = new_rows)) days_that_differ
FROM m JOIN t USING (score_date) WHERE score_date IS NOT NULL"

q "F2: the new gate on today's manifest (expected: blocked = false)" "
SELECT
  MAX(IF(status IN ('partial', 'quarantined'), finished_at, NULL)) last_incomplete,
  MAX(IF(status = 'loaded' AND batch_id LIKE '%all_CVEs_at_midnight%', finished_at, NULL)) last_full_baseline,
  COUNTIF(status IN ('partial', 'quarantined')) incomplete_files_ever
FROM \`$P.ops.ingest_manifest\` WHERE source = 'cvelist'"

q "F5: EPSS text near the 10% threshold (expected: 9.99% / 9.95% / 10.0% / 16.5% / 29.0% / 0.45%)" "
SELECT epss, CONCAT(IF(epss * 100 < 10, FORMAT('%.2f', TRUNC(ROUND(epss * 100, 6), 2)),
                       FORMAT('%.1f', TRUNC(ROUND(epss * 100, 6), 1))), '%') AS shown
FROM UNNEST([0.09999, 0.0995, 0.1, 0.16501, 0.29, 0.0045]) AS epss"

q "F6: precise source dates vs the typed bronze columns (expected: differ only by < 1 second)" "
SELECT COUNT(*) rows_checked,
  COUNTIF(SAFE.TIMESTAMP(JSON_VALUE(record, '\$.cveMetadata.datePublished')) IS NULL) not_parsed,
  COUNTIF(SAFE.TIMESTAMP(JSON_VALUE(record, '\$.cveMetadata.datePublished')) != date_published) with_fraction,
  COUNTIF(ABS(TIMESTAMP_DIFF(SAFE.TIMESTAMP(JSON_VALUE(record, '\$.cveMetadata.datePublished')),
                             date_published, MILLISECOND)) >= 1000) differ_1s_or_more
FROM \`$P.bronze.cvelist_records\` WHERE date_published IS NOT NULL"
