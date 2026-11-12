"""Integration tests against real BigQuery and Cloud Storage, in throwaway resources.
Do not run directly: tests/run_integration.sh creates test_bronze / test_ops and a test bucket,
sets BRONZE_DATASET, OPS_DATASET and BUCKET, runs this file, then deletes everything.
"""
import datetime as dt
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "extractor"))
assert os.environ.get("BRONZE_DATASET", "").startswith("test_"), "refusing to run outside test datasets"
assert os.environ.get("OPS_DATASET", "").startswith("test_"), "refusing to run outside test datasets"
sys.argv = ["main.py", "epss"]
import main  # noqa: E402
from google.cloud import bigquery  # noqa: E402

bq = main.bq
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {name}{('  -- ' + str(detail)) if detail else ''}", flush=True)


def one(sql, **params):
    qp = [bigquery.ScalarQueryParameter(k, "TIMESTAMP" if isinstance(v, dt.datetime) else "STRING", v)
          for k, v in params.items()]
    return list(bq.query(sql, job_config=bigquery.QueryJobConfig(query_parameters=qp)).result())


# ------------------------------------------------------------ 0. schema evolution on an old table
old_kev = bigquery.Table(main.T_KEV, schema=[f for f in main.TABLES[main.T_KEV][0] if f.name != "processed_at"])
old_kev.time_partitioning = bigquery.TimePartitioning(field="observed_at")
bq.create_table(old_kev)
main.ensure_tables()
cols = {f.name for f in bq.get_table(main.T_KEV).schema}
check("0. ensure_tables adds processed_at to a table created with the old schema", "processed_at" in cols)

# ------------------------------------------------------------ 3. EPSS: re-process, no duplicates, conflicts
E = main.T_EPSS
main.run_epss_reprocess()
n1, d1 = one(f"SELECT COUNT(*) n, COUNT(DISTINCT CONCAT(cve_id, CAST(score_date AS STRING))) d FROM `{E}`")[0]
files = one(f"SELECT COUNT(*) n FROM `{main.MANIFEST}` WHERE source='epss' AND status='loaded'")[0].n
check("3a. re-process from raw loads every stored file", files == 2, f"{files} files, {n1:,} rows")
check("3a. one row per (cve_id, score_date)", n1 == d1 and n1 > 0, f"rows {n1:,}, distinct {d1:,}")

days = one(f"SELECT score_date, COUNT(*) n, MIN(observed_at) obs, MIN(processed_at) proc FROM `{E}` GROUP BY 1 ORDER BY 1")
for r in days:
    check(f"3a. {r.score_date}: observed_at is the raw file time, earlier than processed_at",
          r.obs < r.proc, f"{r.n:,} rows, observed {r.obs:%Y-%m-%d %H:%M}, processed {r.proc:%Y-%m-%d %H:%M}")

status = one(f"SELECT COUNTIF(complete) ok, COUNT(*) n FROM `{main.V_EPSS_DAYS}`")[0]
check("3a. ops.epss_day_status (the shared definition) marks both loaded days complete",
      status.ok == 2 and status.n == 2, f"{status.ok}/{status.n} complete")

main.run_epss_reprocess()
n2 = one(f"SELECT COUNT(*) n FROM `{E}`")[0].n
unchanged = one(f"SELECT COUNT(*) n FROM `{main.MANIFEST}` WHERE source='epss' AND status='unchanged'")[0].n
check("3b. running the same files again adds no rows", n2 == n1, f"{n1:,} -> {n2:,}")
check("3b. ...and records them as unchanged", unchanged == 2, unchanged)

blob = next(iter(main.gcs.list_blobs(prefix="raw/epss/")))
model, score_date, rest = main.parse_epss(blob.download_as_bytes())
import csv, io  # noqa: E401,E402
rows = [{"cve_id": r["cve"], "epss": float(r["epss"]), "percentile": float(r["percentile"]),
         "score_date": score_date, "model_version": model, "batch_id": "test-same",
         "observed_at": main.iso(main.now()), "processed_at": main.iso(main.now())}
        for r in csv.DictReader(io.StringIO(rest))]
CMP = ["epss", "percentile", "model_version"]
main.PROCESSOR_VERSION = "2-test-bump"          # a new parser version must re-process stored files
main.run_epss_reprocess()
bumped = one(f"SELECT COUNT(*) n, SUM(records_new) new_rows, SUM(records_conflicting) c FROM `{main.MANIFEST}` "
             f"WHERE source='epss' AND processor='2-test-bump' AND status='loaded'")[0]
n_bump = one(f"SELECT COUNT(*) n FROM `{E}`")[0].n
check("3c. new PROCESSOR_VERSION: the manifest no longer skips the files, they are re-processed",
      bumped.n == 2, f"{bumped.n} files re-processed")
check("3c. ...with the same values: 0 new rows, 0 conflicts",
      bumped.new_rows == 0 and bumped.c == 0 and n_bump == n1, f"new {bumped.new_rows}, conflicts {bumped.c}, rows {n_bump:,}")

changed = [dict(r, epss=round(r["epss"] + 0.1, 5), batch_id="test-changed") for r in rows[:5]]
new, conflicts = main.insert_new_only(E, changed, ["cve_id", "score_date"], compare_cols=CMP)
n3 = one(f"SELECT COUNT(*) n FROM `{E}`")[0].n
check("3d. different value for the same cve_id + score_date is reported, not inserted",
      new == 0 and conflicts == 5 and n3 == n1, f"new {new}, conflicts {conflicts}, rows {n3:,}")

model_only = [dict(r, model_version="v-other") for r in rows[5:9]]
new, conflicts = main.insert_new_only(E, model_only, ["cve_id", "score_date"], compare_cols=CMP)
check("3d. a different model_version alone is also a conflict", new == 0 and conflicts == 4,
      f"new {new}, conflicts {conflicts}")

fresh = [dict(r, score_date="2001-01-01") for r in rows[:2]]
clash = fresh + [dict(fresh[0], epss=0.999)]     # same key twice in one batch, different values
new, conflicts = main.insert_new_only(E, clash, ["cve_id", "score_date"], compare_cols=CMP)
check("3d. one key with two different values inside a first batch: reported and NOTHING inserted",
      conflicts == 1 and new == 0, f"new {new}, conflicts {conflicts}")

dup = rows[:3] + rows[:3]
new, _ = main.insert_new_only(E, [dict(r, score_date="2000-01-01") for r in dup], ["cve_id", "score_date"])
check("3e. duplicates inside one batch are inserted once", new == 3, f"new {new}")

size = bq.get_table(E)
check("3f. size per EPSS day (measured)", True,
      f"{size.num_rows:,} rows, {size.num_bytes / 1e6:.1f} MB logical in total "
      f"= {size.num_bytes / max(1, len(days)) / 1e6:.1f} MB per day")

X = dt.date(1999, 1, 1)                         # synthetic days, far from real data
day = lambda k: (X + dt.timedelta(days=k)).isoformat()  # noqa: E731
def put(k, n_rows, loaded, status="loaded"):
    rows = [{"cve_id": f"CVE-1999-{k}{i:04d}", "epss": 0.1, "percentile": 0.5, "score_date": day(k),
             "model_version": "t", "batch_id": f"epss:{day(k)}:test", "observed_at": main.iso(main.now()),
             "processed_at": main.iso(main.now())} for i in range(n_rows)]
    main.insert_new_only(E, rows, ["cve_id", "score_date"])
    main.manifest(source="epss", batch_id=f"epss:{day(k)}:test", status=status, records_new=loaded,
                  records_in_scope=loaded, target=E)
put(0, 3, 3)                                                     # complete
main.manifest(source="epss", batch_id=f"epss:{day(1)}", status="failed", target=E)   # failed, never loaded
put(2, 2, 2)                                                     # complete, AFTER the hole
put(3, 2, 3)                                                     # table has 2 rows, the file had 3
put(4, 2, 2); main.manifest(source="epss", batch_id=f"epss:{day(4)}:test2", status="conflicts", target=E)
# F4: the INSERT succeeds, then writing the manifest fails; the retry inserts nothing new
import gzip  # noqa: E402
f4_body = gzip.compress((f"#model_version:t,score_date:{day(5)}T12:00:00Z\ncve,epss,percentile\n"
                         + "".join(f"CVE-1999-5{i:04d},0.2,0.6\n" for i in range(3))).encode())
real_manifest, failed_once = main.manifest, []
def flaky_manifest(**r):
    if not failed_once:
        failed_once.append(1)
        raise RuntimeError("injected: manifest write failed after the INSERT")
    real_manifest(**r)
main.manifest = flaky_manifest
try:
    main.ingest_epss(f4_body, "f4 first try", main.now())
    first = "no error"
except RuntimeError as e:
    first = str(e)
retry_date, retry_new = main.ingest_epss(f4_body, "f4 retry", main.now())
main.manifest = real_manifest
f4 = one(f"SELECT complete, file_rows, table_rows FROM `{main.V_EPSS_DAYS}` WHERE score_date = '{day(5)}'")[0]
check("F4. INSERT ok then manifest failed: the first try fails", "injected" in first, first)
check("F4. ...the retry inserts 0 new rows and is recorded loaded", retry_new == 0, retry_new)
check("F4. ...and the day is complete (table rows = the file's rows), not stuck incomplete",
      f4.complete and f4.file_rows == 3 and f4.table_rows == 3, dict(f4.items()))

saved_start = main.COHORT_START_TS
main.COHORT_START_TS = dt.datetime(1999, 1, 1, tzinfo=dt.timezone.utc)
gaps = main.epss_gap_days(day(6))
main.COHORT_START_TS = saved_start
check("3g. gap days on real BigQuery: a failed day behind a later good day, a row-count mismatch, "
      "and a conflict day are all reported (and the F4 day is not)", gaps == [day(1), day(3), day(4)], str(gaps))

# ------------------------------------------------------------ F1: known CVE ids come from bronze
main.load_json_rows(main.T_CVELIST, [{"cve_id": "CVE-1999-0001", "state": "PUBLISHED", "record_hash": "x",
                                      "date_published": "2026-10-20T10:00:00.5Z", "record": {"a": 1}}])
known = main.known_cve_ids()
check("F1. known_cve_ids reads the ids stored in bronze cvelist", "CVE-1999-0001" in known, len(known))
stored = one(f"SELECT FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%E*SZ', date_published) t FROM `{main.T_CVELIST}` "
             f"WHERE cve_id = 'CVE-1999-0001'")[0].t
check("F6. BigQuery keeps the fraction of a second we now send", stored == "2026-10-20T10:00:00.5Z", stored)

# ------------------------------------------------------------ 4. KEV membership per catalog version
t1 = dt.datetime(2026, 11, 1, 12, tzinfo=dt.timezone.utc)
t2 = dt.datetime(2026, 11, 2, 12, tzinfo=dt.timezone.utc)


def entry(cve):
    return {"cveID": cve, "dateAdded": "2026-10-30", "knownRansomwareCampaignUse": "Unknown"}


v1 = {"catalogVersion": "test.1", "vulnerabilities": [entry("CVE-T-A"), entry("CVE-T-B"), entry("CVE-T-C")]}
v2 = {"catalogVersion": "test.2", "vulnerabilities": [entry("CVE-T-A"), entry("CVE-T-C")]}  # B removed
for d, sha, t in ((v1, "a" * 64, t1), (v2, "b" * 64, t2)):
    _, _, members = main.kev_rows(d, sha, t, main.now())
    main.insert_new_only(main.T_KEV_SNAP, members, ["batch_id", "cve_id"])

AS_OF = (f"SELECT ARRAY_AGG(cve_id ORDER BY cve_id) m FROM `{main.T_KEV_SNAP}` WHERE batch_id = ("
         f"SELECT batch_id FROM `{main.T_KEV_SNAP}` WHERE observed_at <= @c "
         f"ORDER BY observed_at DESC, batch_id DESC LIMIT 1)")
before = one(AS_OF, c=t1 + dt.timedelta(hours=1))[0].m
after = one(AS_OF, c=t2 + dt.timedelta(hours=1))[0].m
kept = one(f"SELECT COUNT(*) n FROM `{main.T_KEV_SNAP}` WHERE cve_id='CVE-T-B'")[0].n
check("4a. membership as of the first catalog: A, B, C", before == ["CVE-T-A", "CVE-T-B", "CVE-T-C"], before)
check("4b. membership as of the second catalog: B is gone", after == ["CVE-T-A", "CVE-T-C"], after)
check("4c. B's earlier membership is still stored", kept == 1, kept)
_, _, members = main.kev_rows(v2, "b" * 64, t2, main.now())
new, _ = main.insert_new_only(main.T_KEV_SNAP, members, ["batch_id", "cve_id"])
check("4d. loading the same catalog again adds nothing", new == 0, new)

# A -> B -> A: the manifest is the observation log; catalog A seen again is recorded 'unchanged'
t3 = dt.datetime(2026, 11, 3, 12, tzinfo=dt.timezone.utc)
bA, bB = f"kev:test.1:{'a' * 12}", f"kev:test.2:{'b' * 12}"
for batch, status, t in ((bA, "loaded", t1), (bB, "loaded", t2), (bA, "unchanged", t3)):
    main.manifest(source="kev", batch_id=batch, status=status, target=main.T_KEV, finished_at=main.iso(t))
OBS = (f"SELECT ARRAY_AGG(cve_id ORDER BY cve_id) m FROM `{main.T_KEV_SNAP}` WHERE batch_id = ("
       f"SELECT batch_id FROM `{main.MANIFEST}` WHERE source = 'kev' AND status IN ('loaded', 'unchanged') "
       f"AND finished_at <= @c ORDER BY finished_at DESC LIMIT 1)")
seq = [one(OBS, c=t + dt.timedelta(hours=1))[0].m for t in (t1, t2, t3)]
check("4e. A -> B -> A: membership as of each observation is A, then B, then A again",
      seq == [["CVE-T-A", "CVE-T-B", "CVE-T-C"], ["CVE-T-A", "CVE-T-C"], ["CVE-T-A", "CVE-T-B", "CVE-T-C"]], seq)

print(f"\n{sum(RESULTS)}/{len(RESULTS)} passed")
sys.exit(0 if all(RESULTS) else 1)
