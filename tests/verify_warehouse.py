"""Read-only consistency checks INSIDE the warehouse, on production data: manifest -> bronze -> silver -> gold.

Every check is a SELECT that returns how many rows break a rule ("failing") and a few examples.
Expected: 0 everywhere. Nothing is written. Run after the daily run (not while it is running):
  /tmp/vuln-venv/bin/python tests/verify_warehouse.py
Checks that compare the stored RAW files with the layers are in tests/verify_raw.py.
"""
import sys

from google.cloud import bigquery

P = "vuln-intel-warehouse"
COHORT = "2026-10-08"
bq = bigquery.Client(project=P)
CFG = bigquery.QueryJobConfig(maximum_bytes_billed=5 * 1024 ** 3)   # never more than 5 GiB per query
M = f"`{P}.ops.ingest_manifest`"
B = {t: f"`{P}.bronze.{t}`" for t in ("cvelist_records", "nvd_records", "kev_records", "kev_snapshots", "epss_scores_v2")}
S = {t: f"`{P}.silver.{t}`" for t in ("cve_latest", "nvd_latest", "kev_current", "epss_latest", "cve_metrics", "cvss_selected")}
G, SUMMARY = f"`{P}.gold.cve_current`", f"`{P}.gold.coverage_summary`"
VRANK = "CASE {v} WHEN '4.0' THEN 1 WHEN '3.1' THEN 2 WHEN '3.0' THEN 3 WHEN '2.0' THEN 4 END"
RESULTS = []


def run(name, sql):
    """sql returns one row: failing (INT64) and detail (STRING, examples)."""
    try:
        r = list(bq.query(sql, job_config=CFG).result())[0]
        ok = r.failing == 0
        RESULTS.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  {name}  -- failing {r.failing}"
              f"{('; e.g. ' + r.detail) if r.detail else ''}", flush=True)
    except Exception as e:  # a broken check must show, not hide
        RESULTS.append(False)
        print(f"ERROR {name}  -- {str(e)[:300]}", flush=True)


def examples(expr):
    return f"ARRAY_TO_STRING(ARRAY_AGG(CAST({expr} AS STRING) IGNORE NULLS LIMIT 3), ', ')"


print("== 1. manifest -> bronze (every stored row is accounted for by a recorded file)")
run("manifest: every loaded/partial/conflicts entry names its raw file and a sha256",
    f"""SELECT COUNT(*) failing, {examples("CONCAT(source, ' ', batch_id)")} detail FROM {M}
        WHERE status IN ('loaded', 'partial', 'conflicts')
          AND (file_uri IS NULL OR NOT REGEXP_CONTAINS(IFNULL(sha256, ''), r'^[0-9a-f]{{64}}$'))""")
# 'unchanged' = we downloaded the same file again; it is not stored twice, so it has no file of its own,
# but its sha256 must be the one of a file we stored before
run("manifest: every 'unchanged' entry has a sha256 equal to a file already stored",
    f"""SELECT COUNT(*) failing, {examples("CONCAT(u.source, ' ', u.batch_id)")} detail FROM {M} u
        WHERE u.status = 'unchanged' AND NOT EXISTS (
          SELECT 1 FROM {M} l WHERE l.sha256 = u.sha256 AND l.file_uri IS NOT NULL
            AND l.status IN ('loaded', 'partial', 'conflicts'))""")
# manifest rows written before 9 Nov have no 'target' column value: they are matched by source
for t, src in (("cvelist_records", "cvelist"), ("nvd_records", "nvd"), ("kev_records", "kev"), ("epss_scores_v2", None)):
    which = f"target = '{P}.bronze.{t}'" + (f" OR (target IS NULL AND source = '{src}')" if src else "")
    run(f"bronze.{t}: rows per batch = the rows the manifest says that batch added (no lost, no extra rows)",
        f"""WITH t AS (SELECT batch_id, COUNT(*) n FROM {B[t]} GROUP BY 1),
                 -- records_in_table (since 13 Nov) counts the batch's rows after the load, so it stays right
                 -- after a retry that inserted 0; older entries only have records_new
                 m AS (SELECT batch_id, COALESCE(MAX(records_in_table), SUM(IFNULL(records_new, 0))) n FROM {M}
                       WHERE {which} GROUP BY 1)
            SELECT COUNT(*) failing, {examples("CONCAT(batch_id, ': table ', CAST(IFNULL(t.n, 0) AS STRING), ' vs manifest ', CAST(IFNULL(m.n, 0) AS STRING))")} detail
            FROM t FULL JOIN m USING (batch_id) WHERE IFNULL(t.n, 0) != IFNULL(m.n, 0)""")
# a catalog loaded before kev_snapshots existed (6 Nov) has no membership stored: silver.kev_current never
# uses it (it needs stored members = CISA's count). A catalog with SOME members but not all is a failure.
run("bronze.kev_snapshots: no 'loaded' KEV catalog has a partial membership (some members, not CISA's count)",
    f"""WITH s AS (SELECT batch_id, COUNT(DISTINCT cve_id) n FROM {B['kev_snapshots']} GROUP BY 1)
        SELECT COUNTIF(IFNULL(s.n, 0) > 0) failing,
          {examples("CONCAT(m.batch_id, ': ', CAST(IFNULL(s.n, 0) AS STRING), ' vs ', CAST(m.records_seen AS STRING))")} detail
        FROM {M} m LEFT JOIN s USING (batch_id)
        WHERE m.source = 'kev' AND m.status = 'loaded' AND IFNULL(s.n, 0) != m.records_seen""")
run("ops.epss_day_status: every day from the cohort start to the latest complete day is complete",
    f"""SELECT COUNT(*) failing, {examples("d")} detail
        FROM UNNEST(GENERATE_DATE_ARRAY('{COHORT}', (SELECT MAX(score_date) FROM `{P}.ops.epss_day_status` WHERE complete))) d
        LEFT JOIN `{P}.ops.epss_day_status` s ON s.score_date = d WHERE NOT IFNULL(s.complete, FALSE)""")

print("\n== 2. bronze -> silver (silver re-derived from bronze with the documented rules)")
# silver tables are rebuilt by Dataform (daily); bronze keeps receiving hourly cvelist files after that.
# Re-derive silver only from the bronze rows that existed when silver was built.
SILVER_BUILT = f"""(SELECT TIMESTAMP_MILLIS(last_modified_time) FROM `{P}.silver.__TABLES__`
                      WHERE table_id = 'cve_latest')"""
# processed_at exists only since 9 Nov: older rows have it NULL, and were loaded when they were observed
CVE_ROWS = f"(SELECT * FROM {B['cvelist_records']} WHERE COALESCE(processed_at, observed_at) <= {SILVER_BUILT})"
run("silver.cve_latest: the chosen version of every CVE = the newest stored version (re-derived), scope applied after",
    f"""WITH b AS (
          SELECT cve_id, record_hash, observed_at,
            COALESCE(SAFE.TIMESTAMP(JSON_VALUE(record, '$.cveMetadata.datePublished')), date_published) pub,
            COALESCE(SAFE.TIMESTAMP(JSON_VALUE(record, '$.cveMetadata.dateUpdated')), date_updated) upd
          FROM {CVE_ROWS}
          QUALIFY ROW_NUMBER() OVER (PARTITION BY cve_id ORDER BY COALESCE(upd, pub) DESC, observed_at DESC,
                                     record_hash DESC) = 1),
        expected AS (SELECT cve_id, record_hash FROM b WHERE pub >= TIMESTAMP('{COHORT}'))
        SELECT COUNT(*) failing, {examples("cve_id")} detail
        FROM expected e FULL JOIN (SELECT cve_id, record_hash FROM {S['cve_latest']}) s USING (cve_id)
        WHERE e.record_hash IS DISTINCT FROM s.record_hash""")
run("silver.cve_latest: versions_stored = the versions bronze holds",
    f"""SELECT COUNT(*) failing, {examples("cve_id")} detail FROM {S['cve_latest']} s
        JOIN (SELECT cve_id, COUNT(*) n FROM {CVE_ROWS} GROUP BY 1) b USING (cve_id)
        WHERE s.versions_stored != b.n""")
run("silver.nvd_latest: one row per CVE in bronze NVD, the version with the newest lastModified",
    f"""WITH b AS (SELECT cve_id, record_hash FROM {B['nvd_records']}
                   QUALIFY ROW_NUMBER() OVER (PARTITION BY cve_id ORDER BY
                     COALESCE(SAFE.TIMESTAMP(JSON_VALUE(record, '$.lastModified')), last_modified) DESC,
                     observed_at DESC, record_hash DESC) = 1)
        SELECT COUNT(*) failing, {examples("cve_id")} detail
        FROM b FULL JOIN (SELECT cve_id, record_hash FROM {S['nvd_latest']}) s USING (cve_id)
        WHERE b.record_hash IS DISTINCT FROM s.record_hash""")
run("silver.cve_metrics: every score belongs to a record version stored in bronze (same CVE, same source)",
    f"""SELECT COUNT(*) failing, {examples("cve_id")} detail FROM {S['cve_metrics']} m
        WHERE NOT EXISTS (SELECT 1 FROM {B['cvelist_records']} b
                          WHERE m.ingestion_source = 'cvelist' AND b.cve_id = m.cve_id AND b.record_hash = m.record_hash)
          AND NOT EXISTS (SELECT 1 FROM {B['nvd_records']} b
                          WHERE m.ingestion_source = 'nvd' AND b.cve_id = m.cve_id AND b.record_hash = m.record_hash)""")
run("silver.cvss_selected: the chosen score has the best version available for that CVE (4.0 > 3.1 > 3.0 > 2.0)",
    f"""WITH chosen_versions AS (
          SELECT cve_id, record_hash, 'cvelist' src FROM {S['cve_latest']}
          UNION ALL SELECT cve_id, record_hash, 'nvd' FROM {S['nvd_latest']}),
        best AS (SELECT m.cve_id, MIN({VRANK.format(v='m.cvss_version')}) r
                 FROM {S['cve_metrics']} m JOIN chosen_versions c
                   ON c.cve_id = m.cve_id AND c.record_hash = m.record_hash AND c.src = m.ingestion_source
                 WHERE m.base_score IS NOT NULL AND m.cve_id IN (SELECT cve_id FROM {S['cve_latest']})
                 GROUP BY 1)
        SELECT COUNT(*) failing, {examples("cve_id")} detail
        FROM best b FULL JOIN {S['cvss_selected']} s USING (cve_id)
        WHERE b.r IS DISTINCT FROM {VRANK.format(v='s.cvss_version')}""")
run("silver.cvss_selected: the chosen score, version and vector exist in the chosen record version",
    f"""SELECT COUNT(*) failing, {examples("s.cve_id")} detail FROM {S['cvss_selected']} s
        WHERE NOT EXISTS (SELECT 1 FROM {S['cve_metrics']} m
                          WHERE m.cve_id = s.cve_id AND m.record_hash = s.record_hash AND m.base_score = s.cvss_score
                            AND m.cvss_version = s.cvss_version AND m.vector = s.cvss_vector
                            AND m.ingestion_source = s.cvss_via)""")

print("\n== 3. silver -> gold (every gold value comes from silver, and the rules give the same result)")
run("gold.cve_current: exactly the PUBLISHED CVEs of silver.cve_latest, once each",
    f"""SELECT COUNT(*) failing, {examples("cve_id")} detail
        FROM (SELECT cve_id FROM {S['cve_latest']} WHERE state = 'PUBLISHED') s
        FULL JOIN (SELECT cve_id, COUNT(*) OVER (PARTITION BY cve_id) n FROM {G}) g USING (cve_id)
        WHERE s.cve_id IS NULL OR g.cve_id IS NULL OR g.n > 1""")
run("gold.cve_current: identity, dates, vendor and lineage equal silver.cve_latest",
    f"""SELECT COUNT(*) failing, {examples("g.cve_id")} detail FROM {G} g JOIN {S['cve_latest']} s USING (cve_id)
        WHERE g.published_at IS DISTINCT FROM s.date_published OR g.assigner IS DISTINCT FROM s.assigner
           OR g.title IS DISTINCT FROM s.title OR g.description IS DISTINCT FROM s.description
           OR g.first_listed_vendor IS DISTINCT FROM s.first_listed_vendor
           OR g.first_listed_product IS DISTINCT FROM s.first_listed_product
           OR g.cve_record_hash IS DISTINCT FROM s.record_hash
           OR g.published_at < TIMESTAMP('{COHORT}')""")
run("gold.cve_current: every CVSS field equals silver.cvss_selected (NULL exactly when there is no score)",
    f"""SELECT COUNT(*) failing, {examples("g.cve_id")} detail FROM {G} g LEFT JOIN {S['cvss_selected']} s USING (cve_id)
        WHERE g.cvss_score IS DISTINCT FROM s.cvss_score OR g.cvss_version IS DISTINCT FROM s.cvss_version
           OR g.cvss_vector IS DISTINCT FROM s.cvss_vector OR g.cvss_provider IS DISTINCT FROM s.cvss_provider
           OR g.cvss_via IS DISTINCT FROM s.cvss_via OR g.cvss_record_hash IS DISTINCT FROM s.record_hash""")
run("gold.cve_current: nvd_status and its fingerprint equal silver.nvd_latest",
    f"""SELECT COUNT(*) failing, {examples("g.cve_id")} detail FROM {G} g LEFT JOIN {S['nvd_latest']} n USING (cve_id)
        WHERE g.nvd_status IS DISTINCT FROM n.nvd_status OR g.nvd_record_hash IS DISTINCT FROM n.record_hash""")
run("gold.cve_current: priority re-computed from its own columns with the documented rule (in order)",
    f"""SELECT COUNT(*) failing, {examples("cve_id")} detail FROM {G}
        WHERE priority IS DISTINCT FROM CASE WHEN is_kev THEN 'P1' WHEN epss_score >= 0.10 THEN 'P2'
                                             WHEN cvss_score >= 9.0 THEN 'P3' ELSE 'Other' END""")
run("gold.cve_current: priority_reason agrees with the priority and never prints 'NULL'",
    f"""SELECT COUNT(*) failing, {examples("cve_id")} detail FROM {G}
        WHERE NOT CASE priority
                WHEN 'P1' THEN STARTS_WITH(priority_reason, 'In CISA KEV (added ')
                WHEN 'P2' THEN STARTS_WITH(priority_reason, 'Not in KEV; EPSS ') AND ENDS_WITH(priority_reason, 'threshold of 10%')
                WHEN 'P3' THEN ENDS_WITH(priority_reason, 'is at or above 9.0')
                ELSE STARTS_WITH(priority_reason, 'Not in KEV; ')
                     AND (ENDS_WITH(priority_reason, 'Not assessed as safe.') = (cvss_score IS NULL AND epss_score IS NULL))
              END
           OR CONTAINS_SUBSTR(priority_reason, 'NULL')""")
run("gold.cve_current: missing_data lists exactly the three tracked gaps",
    f"""SELECT COUNT(*) failing, {examples("cve_id")} detail FROM {G}
        WHERE IFNULL(missing_data, '') != ARRAY_TO_STRING(ARRAY(
          SELECT x FROM UNNEST([IF(cvss_score IS NULL, 'no CVSS', NULL), IF(epss_score IS NULL, 'no EPSS', NULL),
                                IF(nvd_status IS NULL, 'not in NVD data', NULL)]) x WITH OFFSET o
          WHERE x IS NOT NULL ORDER BY o), '; ')""")
run("gold.cve_current: one EPSS day, one KEV catalog and one build time for the whole result",
    f"""SELECT (COUNT(DISTINCT epss_score_date) + COUNT(DISTINCT kev_catalog_version) + COUNT(DISTINCT kev_checked_at)
               + COUNT(DISTINCT updated_at)) - 4 failing,
            CAST(NULL AS STRING) detail FROM {G}""")
run("gold.coverage_summary: every number equals a fresh count of gold.cve_current",
    f"""WITH c AS (SELECT COUNT(*) n, COUNTIF(is_kev) k, COUNTIF(priority = 'P1') p1, COUNTIF(priority = 'P2') p2,
                          COUNTIF(priority = 'P3') p3, COUNTIF(priority = 'Other') o,
                          ROUND(100 * COUNTIF(cvss_score IS NULL) / COUNT(*), 1) wc,
                          ROUND(100 * COUNTIF(epss_score IS NULL) / COUNT(*), 1) we FROM {G})
        SELECT COUNTIF(s.cves_in_scope != c.n OR s.in_kev != c.k OR s.p1 != c.p1 OR s.p2 != c.p2
                       OR s.p3 != c.p3 OR s.other != c.o OR s.pct_without_cvss != c.wc OR s.pct_without_epss != c.we
                       OR s.p1 + s.p2 + s.p3 + s.other != s.cves_in_scope) failing,
               CAST(NULL AS STRING) detail FROM {SUMMARY} s CROSS JOIN c""")

print("\n== 4. operations (is the pipeline running on time?)")
run("gold.cve_current: built in the last 26 hours (the daily run published it)",
    f"""SELECT COUNTIF(t < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 26 HOUR)) failing, CAST(MAX(t) AS STRING) detail
        FROM (SELECT MAX(updated_at) t FROM {G})""")
run("ops.source_watermarks: cvelist checked in the last 3 hours, NVD/KEV/EPSS in the last 30",
    f"""SELECT COUNTIF(last_checked_at < TIMESTAMP_SUB(CURRENT_TIMESTAMP(),
                       INTERVAL IF(source = 'cvelist', 3, 30) HOUR)) failing,
               {examples("CONCAT(source, ' ', CAST(last_checked_at AS STRING))")} detail
        FROM (SELECT source, MAX(last_checked_at) last_checked_at FROM `{P}.ops.source_watermarks` GROUP BY 1)""")
# each run writes a 'started' row and an end row ('succeeded' or 'failed'); a run with no end row after
# 2 hours (the job timeout is 1 hour) crashed without recording its end
run("ops.ingest_runs: in the last 24 hours, no failed run and no run that never finished",
    f"""WITH r AS (SELECT run_id, ANY_VALUE(mode) mode, MIN(started_at) started_at,
                         LOGICAL_OR(status = 'failed') failed, LOGICAL_OR(status IN ('succeeded', 'failed')) ended,
                         STRING_AGG(error, ' ') error
                  FROM `{P}.ops.ingest_runs` GROUP BY 1)
        SELECT COUNTIF(failed OR (NOT ended AND started_at < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 HOUR))) failing,
          {examples("IF(failed OR NOT ended, CONCAT(mode, ' ', CAST(started_at AS STRING), IF(failed, ' failed: ', ' never finished'), SUBSTR(IFNULL(error, ''), 1, 80)), NULL)")} detail
        FROM r WHERE started_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)""")
# older failures are shown, not counted: each one needs its cause and proof it was recovered
for r in bq.query(f"""SELECT run_id, ANY_VALUE(mode) mode, MIN(started_at) t, STRING_AGG(error, ' ') err
                     FROM `{P}.ops.ingest_runs` GROUP BY run_id HAVING LOGICAL_OR(status = 'failed')
                     AND MIN(started_at) >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY) ORDER BY t""",
                  job_config=CFG).result():
    print(f"INFO  failed run in the last 7 days: {r.mode} {r.t:%Y-%m-%d %H:%M} UTC  {r.run_id}  {(r.err or '(no message)')[:120]}")

print(f"\n{sum(RESULTS)}/{len(RESULTS)} passed")
sys.exit(0 if all(RESULTS) else 1)
