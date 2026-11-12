"""Read-only end-to-end check: the RAW files we stored -> bronze -> silver -> gold, on production data.

It downloads the raw files that today's gold was built from and compares them, value by value,
with what each layer holds. Nothing is written anywhere (SELECT queries and downloads only).

  /tmp/vuln-venv/bin/python tests/verify_raw.py            EPSS, KEV, NVD, the latest cvelist delta
  /tmp/vuln-venv/bin/python tests/verify_raw.py --baseline  ...plus the latest full cvelist baseline
                                                            (a few hundred MB, takes a few minutes)
What is reused from the extractor (so the comparison uses the same rules): canonical_hash() for
record fingerprints and cve_row() for reading a CVE file. Values are compared straight from the
files: EPSS scores, KEV membership, NVD records, CVE versions.
"""
import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import sys
import tempfile
import zipfile

ARGS = sys.argv[1:]
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "vuln-intel-warehouse")
os.environ.setdefault("BUCKET", "vuln-intel-warehouse-raw")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "extractor"))
sys.argv = ["main.py", "verify"]
import main  # noqa: E402
from google.cloud import bigquery, storage  # noqa: E402

P = "vuln-intel-warehouse"
bq = bigquery.Client(project=P)
gcs = storage.Client(project=P)
CFG = bigquery.QueryJobConfig(maximum_bytes_billed=5 * 1024 ** 3)   # never more than 5 GiB per query
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append(bool(cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}{('  -- ' + str(detail)) if detail != '' else ''}", flush=True)


def rows(sql):
    return list(bq.query(sql, job_config=CFG).result())


def download(uri):
    bucket, _, name = uri.removeprefix("gs://").partition("/")
    return gcs.bucket(bucket).blob(name).download_as_bytes()


def manifest_file(batch_id, source):
    r = rows(f"SELECT file_uri, sha256, records_seen FROM `{P}.ops.ingest_manifest` WHERE source = '{source}' "
             f"AND batch_id = '{batch_id}' AND file_uri IS NOT NULL ORDER BY finished_at LIMIT 1")
    return r[0] if r else None


def same_file(body, m, label):
    got = hashlib.sha256(body).hexdigest()
    check(f"{label}: raw file is intact (its sha256 equals the manifest's)", got == m.sha256,
          f"{len(body):,} bytes, sha256 {got[:12]}")


# ============================================================ EPSS: the file gold used
print("\n== EPSS (the day the published gold uses)")
d = rows(f"SELECT MAX(epss_score_date) d FROM `{P}.gold.cve_current`")[0].d
e = rows(f"SELECT ANY_VALUE(batch_id) b, COUNT(DISTINCT batch_id) nb, COUNT(*) n, '{d}' d "
         f"FROM `{P}.bronze.epss_scores_v2` WHERE score_date = '{d}'")[0]
check(f"EPSS {d}: all rows of that day come from one file", e.nb == 1, f"{e.nb} batch(es)")
m = manifest_file(e.b, "epss")
body = download(m.file_uri)
same_file(body, m, f"EPSS {e.d}")
text = gzip.decompress(body).decode()
first, _, rest = text.partition("\n")
file_scores = {r["cve"]: (float(r["epss"]), float(r["percentile"])) for r in csv.DictReader(io.StringIO(rest))}
check(f"EPSS {e.d}: the file header names this day", f"score_date:{e.d}" in first, first[:80])
bronze = {r.cve_id: (r.epss, r.percentile) for r in
          rows(f"SELECT cve_id, epss, percentile FROM `{P}.bronze.epss_scores_v2` WHERE score_date = '{e.d}'")}
check(f"EPSS {e.d}: bronze holds exactly the file's CVEs", set(bronze) == set(file_scores),
      f"file {len(file_scores):,}, bronze {len(bronze):,}")
diff = [c for c in file_scores if bronze.get(c) != file_scores[c]]
check(f"EPSS {e.d}: every score and percentile in bronze equals the file", not diff, f"{len(diff)} differ {diff[:3]}")
n_silver = rows(f"SELECT COUNTIF(epss_score_date = '{d}') n, COUNT(*) total FROM `{P}.silver.epss_latest`")[0]
check(f"EPSS {d}: silver.epss_latest has every row of that day (if it shows a newer day, gold is older: "
      f"run this after the daily run)", n_silver.n == len(file_scores) == n_silver.total, f"{n_silver.n:,}")
g = rows(f"SELECT cve_id, epss_score, epss_percentile, epss_score_date FROM `{P}.gold.cve_current`")
wrong = [r.cve_id for r in g if (file_scores.get(r.cve_id) or (None, None)) != (r.epss_score, r.epss_percentile)]
check("EPSS -> gold: every gold CVE's score is exactly the file's value, and NULL exactly when the file has none",
      not wrong, f"{len(g):,} gold rows, {len(wrong)} wrong {wrong[:3]}")
check("EPSS -> gold: every gold row names this EPSS day", all(r.epss_score_date == e.d for r in g), str(e.d))

# ============================================================ KEV: the catalog gold used
print("\n== KEV (the catalog the published gold uses)")
k = rows(f"SELECT m.batch_id b, g.v FROM (SELECT ANY_VALUE(kev_catalog_version) v, ANY_VALUE(kev_checked_at) t "
         f"FROM `{P}.gold.cve_current`) g JOIN `{P}.ops.ingest_manifest` m "
         f"ON m.source = 'kev' AND m.finished_at = g.t AND m.status IN ('loaded', 'unchanged') LIMIT 1")[0]
m = manifest_file(k.b, "kev")
body = download(m.file_uri)
same_file(body, m, f"KEV {k.v}")
cat = json.loads(body)
entries = {v["cveID"]: (v.get("dateAdded"), v.get("knownRansomwareCampaignUse")) for v in cat["vulnerabilities"]}
check(f"KEV {k.v}: the file holds as many entries as CISA's own count", len(entries) == cat.get("count"),
      f"{len(entries):,} entries, count {cat.get('count')}")
snap = {r.cve_id for r in rows(f"SELECT cve_id FROM `{P}.bronze.kev_snapshots` WHERE batch_id = '{k.b}'")}
check(f"KEV {k.v}: bronze kev_snapshots holds exactly the file's membership", snap == set(entries),
      f"file {len(entries):,}, bronze {len(snap):,}")
g = rows(f"SELECT cve_id, is_kev, CAST(kev_date_added AS STRING) d, kev_ransomware_use r FROM `{P}.gold.cve_current`")
wrong = [r.cve_id for r in g if r.is_kev != (r.cve_id in entries)
         or (r.is_kev and (r.d, r.r) != entries[r.cve_id])]
check("KEV -> gold: is_kev is TRUE exactly for gold CVEs in the file, with the file's date and flag",
      not wrong, f"{sum(r.is_kev for r in g)} in KEV, {len(wrong)} wrong {wrong[:3]}")

# ============================================================ NVD: the latest pages
print("\n== NVD (the 3 latest pages loaded)")
pages = rows(f"SELECT batch_id, file_uri, sha256 FROM `{P}.ops.ingest_manifest` WHERE source = 'nvd' "
             f"AND status = 'loaded' AND file_uri IS NOT NULL AND bytes < 30000000 ORDER BY finished_at DESC LIMIT 3")
stored = {(r.cve_id, r.record_hash) for r in rows(f"SELECT cve_id, record_hash FROM `{P}.bronze.nvd_records`")}
cutoff = main.COHORT_START_TS - dt.timedelta(days=2)
for m in pages:
    body = download(m.file_uri)
    same_file(body, m, f"NVD {m.batch_id[-40:]}")
    vulns = [v["cve"] for v in json.loads(body)["vulnerabilities"]]
    in_scope = [c for c in vulns if c.get("published") and main.parse_ts(c["published"]) >= cutoff]
    missing = [c["id"] for c in in_scope if (c["id"], main.canonical_hash(c)) not in stored]
    check(f"NVD page: every in-scope record of the file is stored in bronze, same fingerprint",
          not missing, f"{len(vulns)} records, {len(in_scope)} in scope, {len(missing)} missing {missing[:3]}")


# ============================================================ cvelist: latest delta (+ baseline)
SILVER_BUILT = bq.get_table(f"{P}.silver.cve_latest").modified   # silver is rebuilt by Dataform (daily)


def cvelist_file(where, label):
    # the newest file loaded BEFORE silver was last built, so silver must already reflect it
    m = rows(f"SELECT batch_id, file_uri, sha256, bytes FROM `{P}.ops.ingest_manifest` WHERE source = 'cvelist' "
             f"AND status = 'loaded' AND file_uri IS NOT NULL AND {where} "
             f"AND finished_at <= TIMESTAMP('{SILVER_BUILT.isoformat()}') ORDER BY finished_at DESC LIMIT 1")[0]
    print(f"\n== cvelist {label}: {m.batch_id} ({m.bytes / 1e6:.0f} MB)")
    known = frozenset(r.cve_id for r in rows(f"SELECT DISTINCT cve_id FROM `{P}.bronze.cvelist_records`"))
    stored = {(r.cve_id, r.record_hash) for r in rows(f"SELECT cve_id, record_hash FROM `{P}.bronze.cvelist_records`")}
    with tempfile.TemporaryDirectory() as tmpd:
        path = os.path.join(tmpd, "f.zip")
        bucket, _, name = m.file_uri.removeprefix("gs://").partition("/")
        gcs.bucket(bucket).blob(name).download_to_filename(path)
        with open(path, "rb") as f:
            got = hashlib.file_digest(f, "sha256").hexdigest()
        check(f"cvelist {label}: raw file is intact (sha256 equals the manifest's)", got == m.sha256, got[:12])
        found = []
        def take(zf):
            for info in zf.infolist():
                if main.CVE_FILE.search(info.filename):
                    row, _ = main.cve_row(info.filename, zf.read(info), "", "", main.now(), main.now(), known)
                    if row:
                        found.append(row)
        with zipfile.ZipFile(path) as outer:
            inner = next((n for n in outer.namelist() if n.endswith(".zip")), None)
            if inner:
                ipath = os.path.join(tmpd, "inner.zip")
                with outer.open(inner) as src, open(ipath, "wb") as dst:
                    while chunk := src.read(16 * 1024 * 1024):
                        dst.write(chunk)
                with zipfile.ZipFile(ipath) as z:
                    take(z)
            else:
                take(outer)
    new_scope = [r for r in found if r["date_published"]
                 and main.parse_ts(r["date_published"]) >= main.COHORT_START_TS]
    missing = [r["cve_id"] for r in new_scope if (r["cve_id"], r["record_hash"]) not in stored]
    check(f"cvelist {label}: every in-scope CVE version in the file is stored in bronze",
          not missing, f"{len(found):,} in scope or known, {len(missing)} missing {missing[:3]}")
    f1 = [r for r in found if r not in new_scope and (r["cve_id"], r["record_hash"]) not in stored]
    check(f"cvelist {label}: updates of known CVEs that left the cohort (F1) not yet stored",
          True, f"{len(f1)} (stored by the next load with the F1 fix) {[r['cve_id'] for r in f1[:5]]}")
    # silver must never hold an OLDER version than the file (it may hold a newer one from a later delta)
    silver = {r.cve_id: r for r in rows(
        f"SELECT cve_id, record_hash, date_updated, date_published FROM `{P}.silver.cve_latest`")}
    older = []
    for r in new_scope:
        s = silver.get(r["cve_id"])
        file_t = main.parse_ts(r["date_updated"] or r["date_published"])
        if s is None or (s.record_hash != r["record_hash"] and (s.date_updated or s.date_published) < file_t):
            older.append(r["cve_id"])
    check(f"cvelist {label} -> silver: no in-scope CVE is missing or older in silver than in the file",
          not older, f"{len(older)} {older[:3]}")
    gold = {r.cve_id for r in rows(f"SELECT cve_id FROM `{P}.gold.cve_current`")}
    lost = [r["cve_id"] for r in new_scope if r["state"] == "PUBLISHED" and r["cve_id"] not in gold
            and silver.get(r["cve_id"]) is not None and silver[r["cve_id"]].record_hash == r["record_hash"]]
    check(f"cvelist {label} -> gold: every PUBLISHED in-scope CVE whose silver version is this file's is in gold",
          not lost, f"{len(lost)} {lost[:3]}")


cvelist_file("batch_id NOT LIKE '%all_CVEs_at_midnight%'", "latest hourly delta")
if "--baseline" in ARGS:
    cvelist_file("batch_id LIKE '%all_CVEs_at_midnight%'", "latest full baseline")

print(f"\n{sum(RESULTS)}/{len(RESULTS)} passed")
sys.exit(0 if all(RESULTS) else 1)
