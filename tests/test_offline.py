"""Offline unit tests for extractor/main.py: no network, no Google Cloud.
Google client libraries are replaced with stubs, so this runs anywhere:
    python3 tests/test_offline.py
"""
import contextlib
import datetime as dt
import json
import os
import sys
import tempfile
import types
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "extractor"))


class PreconditionFailed(Exception):
    pass


class NotFound(Exception):
    pass


for name in ["google", "google.cloud", "google.cloud.storage", "google.cloud.bigquery",
             "google.auth", "google.auth.transport", "google.auth.transport.requests"]:
    sys.modules[name] = mock.MagicMock()
sys.modules["google.api_core"] = mock.MagicMock()
sys.modules["google.api_core.exceptions"] = types.SimpleNamespace(
    PreconditionFailed=PreconditionFailed, NotFound=NotFound, Conflict=Exception)
sys.argv = ["main.py", "hourly"]
import main  # noqa: E402

main.time.sleep = lambda *_: None
main.log.disabled = True
main.rows_in_table = lambda table_id, batch_id, where='TRUE': None  # BigQuery count: tested in integration_bq.py
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {name}{('  -- ' + detail) if detail else ''}")


# ---------------------------------------------------------------- fake GCS with generations
class FakeBlob:
    store = {}  # name -> (generation, bytes, updated)

    created = {}  # name -> first creation time

    def __init__(self, name):
        self.name = name
        self.generation = None
        self.updated = None
        self.time_created = None

    def upload_from_string(self, data, if_generation_match=None, **_):
        cur = self.store.get(self.name)
        cur_gen = cur[0] if cur else 0
        if if_generation_match is not None and if_generation_match != cur_gen:
            raise PreconditionFailed(self.name)
        data = data.encode() if isinstance(data, str) else data
        self.store[self.name] = (cur_gen + 1, data, main.now())
        self.created.setdefault(self.name, main.now())

    def reload(self):
        gen, _, upd = self.store[self.name]
        self.generation, self.updated, self.time_created = gen, upd, self.created[self.name]

    def download_as_bytes(self, if_generation_match=None):
        gen, data, _ = self.store[self.name]
        if if_generation_match is not None and if_generation_match != gen:
            raise PreconditionFailed(self.name)
        return data

    def delete(self, if_generation_match=None):
        cur = self.store.get(self.name)
        if cur is None:
            raise NotFound(self.name)
        if if_generation_match is not None and if_generation_match != cur[0]:
            raise PreconditionFailed(self.name)
        del self.store[self.name]


main.gcs = types.SimpleNamespace(blob=FakeBlob)


# ---------------------------------------------------------------- Test 1: interrupted download
class FakeResponse:
    def __init__(self, chunks, fail_after=None):
        self.status_code, self.headers, self.text = 200, {}, ""
        self.chunks, self.fail_after = chunks, fail_after

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_content(self, _size):
        for i, c in enumerate(self.chunks):
            if self.fail_after is not None and i == self.fail_after:
                raise ConnectionError("connection reset in the middle of the download")
            yield c


responses = iter([FakeResponse([b"PART-", b"NEVER"], fail_after=1), FakeResponse([b"FULL-", b"FILE"])])
main.http = types.SimpleNamespace(get=lambda *a, **k: next(responses))
with tempfile.NamedTemporaryFile() as tmp:
    main.fetch("https://example/file.zip", "test file", stream_to=tmp)
    content = open(tmp.name, "rb").read()
check("1. interrupted download then retry gives the complete file only",
      content == b"FULL-FILE", f"got {content!r}")

# ---------------------------------------------------------------- Test 2a: one writer for EPSS
check("2a. epss, epss_backfill and epss_reprocess share one lock",
      main.LOCK_FOR["epss_backfill"] == "epss" and main.LOCK_FOR["epss_reprocess"] == "epss"
      and main.LOCK_FOR.get("epss", "epss") == "epss")

FakeBlob.store.clear()
main.RUN_ID = "run-A"
lock_a = main.Lock(main.LOCK_FOR.get("epss", "epss")).__enter__()       # daily's EPSS step holds it
main.RUN_ID = "run-B"
try:
    main.Lock(main.LOCK_FOR["epss_backfill"]).__enter__()
    blocked = False
except RuntimeError as e:
    blocked = "another run holds locks/epss.lock" in str(e)
check("2a. a second run (epss_backfill) is refused while epss holds the lock", blocked)
main.RUN_ID = "run-A"
lock_a.__exit__(None, None, None)
main.RUN_ID = "run-B"
lock_b = main.Lock(main.LOCK_FOR["epss_backfill"]).__enter__()
check("2a. after release, the other run gets the lock", lock_b.gen is not None)
lock_b.__exit__(None, None, None)

# ---------------------------------------------------------------- Test 2b: backfill reports gaps
main.COHORT_START_TS = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
main.now = lambda: dt.datetime(2026, 11, 5, 12, tzinfo=dt.timezone.utc)
attempted, manifests = [], []


def fake_fetch(url, what, **_):
    day = url.rsplit("-", 3)[-3:]
    day = "-".join(day).replace(".csv.gz", "")
    attempted.append(day)
    if day == "2026-11-03":
        raise RuntimeError("HTTP 404: not found")
    return day.encode()


with mock.patch.object(main, "fetch", fake_fetch), \
     mock.patch.object(main, "ingest_epss", lambda body, *a, **k: (body.decode(), 100)), \
     mock.patch.object(main, "manifest", lambda **r: manifests.append(r)):
    try:
        main.run_epss_backfill()
        raised = None
    except RuntimeError as e:
        raised = str(e)
check("2b. backfill tries every day from COHORT_START to yesterday",
      attempted == ["2026-11-01", "2026-11-02", "2026-11-03", "2026-11-04"], str(attempted))
check("2b. a failed day makes the run fail and names the day",
      raised is not None and "2026-11-03" in raised, str(raised))
check("2b. the failed day is written to the manifest as failed",
      any(m.get("status") == "failed" and m.get("batch_id") == "epss:2026-11-03" for m in manifests))

# ---------------------------------------------------------------- cvelist record checks
main.COHORT_START_TS = dt.datetime(2026, 10, 8, tzinfo=dt.timezone.utc)
T = dt.datetime(2026, 11, 9, tzinfo=dt.timezone.utc)


def rec(cve_id, published="2026-10-20T10:00:00Z", **meta):
    m = {"cveId": cve_id, "state": "PUBLISHED", "datePublished": published, "dateUpdated": published}
    m.update(meta)
    return json.dumps({"dataVersion": "5.1", "cveMetadata": m}).encode()


cases = {
    "in scope": (rec("CVE-2026-1000"), "row"),
    "published before cohort": (rec("CVE-2026-1001", "2026-10-07T23:59:00Z"), "skip"),
    "rejected before publish (no datePublished)": (rec("CVE-2026-1002", None, state="REJECTED"), "skip"),
    "cveId does not match file name": (rec("CVE-2026-9999"), "problem"),
    "cveMetadata is not an object": (json.dumps({"dataVersion": "5.1", "cveMetadata": "x"}).encode(), "problem"),
    "bad date": (rec("CVE-2026-1005", "not-a-date"), "problem"),
    "date is a number": (rec("CVE-2026-1007", 1730000000), "problem"),
    "unsupported dataVersion": (json.dumps({"dataVersion": "4.0", "cveMetadata": {"cveId": "CVE-2026-1006"}}).encode(),
                                "problem"),
}
names = {"in scope": "CVE-2026-1000", "published before cohort": "CVE-2026-1001",
         "rejected before publish (no datePublished)": "CVE-2026-1002",
         "cveId does not match file name": "CVE-2026-1003", "cveMetadata is not an object": "CVE-2026-1004",
         "bad date": "CVE-2026-1005", "unsupported dataVersion": "CVE-2026-1006",
         "date is a number": "CVE-2026-1007"}
for label, (raw, expect) in cases.items():
    row, problem = main.cve_row(f"cves/2026/1xxx/{names[label]}.json", raw, "b", "gs://x", T, T)
    got = "row" if row else ("problem" if problem else "skip")
    check(f"cvelist: {label} -> {expect}", got == expect, problem or "")

# ---------------------------------------------------------------- SQL shape
main.TABLES[main.T_EPSS] = ([types.SimpleNamespace(name=n) for n in
                             ["cve_id", "epss", "percentile", "score_date", "model_version", "batch_id",
                              "observed_at", "processed_at"]], "score_date", ["cve_id"])  # stubs have no names
conflict_q, insert_q = main.insert_sql(main.T_EPSS, "p.d.stage_x", ["cve_id", "score_date"], ["epss", "percentile"])
check("SQL: insert de-duplicates inside the batch and skips stored keys",
      "QUALIFY ROW_NUMBER() OVER (PARTITION BY cve_id, score_date" in insert_q and "WHERE NOT EXISTS" in insert_q)
check("SQL: conflicts compare values with IS DISTINCT FROM",
      conflict_q is not None and "t.epss IS DISTINCT FROM s.epss" in conflict_q)
check("SQL: conflicts also count one key with different values inside the batch",
      "HAVING COUNT(DISTINCT TO_JSON_STRING(STRUCT(epss, percentile))) > 1" in conflict_q)

# ---------------------------------------------------------------- land(): one stable clock
import gzip  # noqa: E402

FakeBlob.store.clear()
FakeBlob.created.clear()
times = iter([dt.datetime(2026, 11, 9, 1, tzinfo=dt.timezone.utc), dt.datetime(2026, 11, 9, 5, tzinfo=dt.timezone.utc)])
with mock.patch.object(main, "now", lambda: next(times, dt.datetime(2026, 11, 9, 9, tzinfo=dt.timezone.utc))):
    _, first = main.land("kev", "same.json", data=b"x")
    _, again = main.land("kev", "same.json", data=b"x")
check("land: observed time is the object's creation time, the same on every later landing",
      first == again and first is not None, f"{first} / {again}")

# ---------------------------------------------------------------- EPSS: wrong day is refused
body = gzip.compress(b"#model_version:v2026.06.15,score_date:2026-11-02T12:55:00Z\n"
                     b"cve,epss,percentile\nCVE-2026-0001,0.1,0.5\n")
landed = []
with mock.patch.object(main, "already_loaded", lambda *a: False), \
     mock.patch.object(main, "land", lambda *a, **k: landed.append(a) or ("gs://x", main.now())):
    try:
        main.ingest_epss(body, "backfill", main.now(), expected_date="2026-11-03")
        refused = None
    except RuntimeError as e:
        refused = str(e)
check("epss_backfill: a file whose score_date is another day is refused before anything is stored",
      refused is not None and "2026-11-02" in refused and not landed, str(refused))

# ---------------------------------------------------------------- EPSS: conflicts fail the run
manifests.clear()
with mock.patch.object(main, "already_loaded", lambda *a: False), \
     mock.patch.object(main, "land", lambda *a, **k: ("gs://x", main.now())), \
     mock.patch.object(main, "insert_new_only", lambda *a, **k: (0, 7)), \
     mock.patch.object(main, "manifest", lambda **r: manifests.append(r)):
    try:
        main.ingest_epss(body, "current", main.now())
        failed = None
    except RuntimeError as e:
        failed = str(e)
check("EPSS conflicts: recorded in the manifest, then the run fails (no report on top of them)",
      failed is not None and manifests and manifests[-1]["status"] == "conflicts"
      and manifests[-1]["records_conflicting"] == 7, str(failed))

# ---------------------------------------------------------------- run_kev(): load, then hash skip
catalog = json.dumps({"catalogVersion": "2026.11.06", "count": 2, "dateReleased": "2026-11-06T12:00:00Z",
                      "vulnerabilities": [{"cveID": "CVE-1"}, {"cveID": "CVE-2"}]}).encode()
seen_sha, manifests, inserted = set(), [], []
with mock.patch.object(main, "fetch", lambda *a, **k: catalog), \
     mock.patch.object(main, "land", lambda *a, **k: ("gs://raw/kev", T)), \
     mock.patch.object(main, "already_loaded", lambda sha, target: sha in seen_sha), \
     mock.patch.object(main, "insert_new_only", lambda t, rows, *a, **k: inserted.append((t, len(rows))) or (len(rows), 0)), \
     mock.patch.object(main, "manifest", lambda **r: (manifests.append(r), seen_sha.add(r["sha256"]))), \
     mock.patch.object(main, "watermark_set", lambda *a, **k: None):
    main.run_kev()
    main.run_kev()
check("run_kev: first run loads records and the full membership",
      inserted == [(main.T_KEV, 2), (main.T_KEV_SNAP, 2)] and manifests[0]["status"] == "loaded", str(inserted))
check("run_kev: same catalog again is skipped, and the observation is still recorded with the same batch_id",
      len(inserted) == 2 and manifests[1]["status"] == "unchanged"
      and manifests[1]["batch_id"] == manifests[0]["batch_id"], f"{manifests[1].get('batch_id')}")

# ---------------------------------------------------------------- EPSS daily fills missed days
calls, manifests = [], []
with mock.patch.object(main, "fetch", lambda url, what, **k: url.encode()), \
     mock.patch.object(main, "epss_gap_days", lambda d: ["2026-11-09"] if d == "2026-11-10" else []), \
     mock.patch.object(main, "ingest_epss",
                       lambda body, label, *a, **k: calls.append((label, k.get("expected_date"))) or
                       ("2026-11-10" if label == "current" else k["expected_date"], 10)), \
     mock.patch.object(main, "watermark_set", lambda *a, **k: None):
    total = main.run_epss()
check("EPSS daily: after the current file, a missed day is fetched from the dated file",
      calls == [("current", None), ("gap fill 2026-11-09", "2026-11-09")] and total == 20, str(calls))

calls = []
with mock.patch.object(main, "fetch", lambda url, what, **k: url.encode()), \
     mock.patch.object(main, "epss_gap_days", lambda d: ["2026-11-08", "2026-11-09"]), \
     mock.patch.object(main, "ingest_epss",
                       lambda body, label, *a, **k: ("2026-11-10", 1) if label == "current" else
                       (_ for _ in ()).throw(RuntimeError("HTTP 404")) if "11-08" in label else ("2026-11-09", 1)), \
     mock.patch.object(main, "manifest", lambda **r: manifests.append(r)), \
     mock.patch.object(main, "watermark_set", lambda *a, **k: None):
    try:
        main.run_epss()
        gap_err = None
    except RuntimeError as e:
        gap_err = str(e)
check("EPSS daily: a gap day that cannot be fetched fails the run and is named",
      gap_err is not None and "2026-11-08" in gap_err and "2026-11-09" not in gap_err
      and manifests[-1]["status"] == "failed", str(gap_err))

# epss_gap_days: the SQL is built from expected days (the logic itself is tested on real BigQuery)
captured = {}
def fake_query(q, job_config=None):
    captured["q"] = q
    return types.SimpleNamespace(result=lambda: [types.SimpleNamespace(day="2026-11-09")])
with mock.patch.object(main, "bq", types.SimpleNamespace(query=fake_query)):
    gaps = main.epss_gap_days("2026-11-11")
check("epss_gap_days: expected days come from GENERATE_DATE_ARRAY joined to the shared status view",
      gaps == ["2026-11-09"] and "GENERATE_DATE_ARRAY" in captured["q"] and main.V_EPSS_DAYS in captured["q"])
check("epss_day_status: complete needs a load, no conflict, and table rows = the file's rows (> 0)",
      all(x in main.epss_day_status_sql() for x in ("ok_loads", "conflict_rows", "table_rows = file_rows", "table_rows = file_rows_min")))

# run_epss: after the gap fill, the final check covers the current day too
with mock.patch.object(main, "fetch", lambda url, what, **k: url.encode()), \
     mock.patch.object(main, "epss_gap_days", lambda d: ["2026-11-10"] if d == "2026-11-11" else []), \
     mock.patch.object(main, "ingest_epss", lambda body, label, *a, **k: ("2026-11-10", 0)), \
     mock.patch.object(main, "watermark_set", lambda *a, **k: None):
    try:
        main.run_epss()
        final_err = None
    except RuntimeError as e:
        final_err = str(e)
check("run_epss: the current day itself still incomplete ('unchanged' but rows differ) -> the run fails",
      final_err is not None and "2026-11-10" in final_err, str(final_err))

# insert_new_only: a batch with conflicts inserts nothing
ran = []
def q2(q, job_config=None):
    ran.append("INSERT" if q.startswith("INSERT") else "CHECK")
    return types.SimpleNamespace(result=lambda: [types.SimpleNamespace(n=2)], num_dml_affected_rows=0)
fake = types.SimpleNamespace(query=q2, create_table=lambda *a, **k: None, delete_table=lambda *a, **k: None)
with mock.patch.object(main, "bq", fake), mock.patch.object(main, "load_json_rows", lambda *a, **k: None):
    res = main.insert_new_only(main.T_EPSS, [{"cve_id": "x"}], ["cve_id", "score_date"], compare_cols=["epss"])
check("insert_new_only: with conflicts, the INSERT is never run", res == (0, 2) and "INSERT" not in ran, str(ran))
check("conflicts is not a done status (a conflicting file is re-checked, never 'unchanged')",
      "conflicts" not in main.DONE_STATUSES)

# run_kev: CISA's own count is compared with the entries read
bad = json.dumps({"catalogVersion": "x", "count": 3, "vulnerabilities": [{"cveID": "CVE-1"}]}).encode()
manifests = []
with mock.patch.object(main, "fetch", lambda *a, **k: bad), \
     mock.patch.object(main, "land", lambda *a, **k: ("gs://raw/kev", T)), \
     mock.patch.object(main, "already_loaded", lambda *a: False), \
     mock.patch.object(main, "insert_new_only", lambda *a, **k: (1, 0)), \
     mock.patch.object(main, "manifest", lambda **r: manifests.append(r)), \
     mock.patch.object(main, "watermark_set", lambda *a, **k: None):
    try:
        main.run_kev()
        kev_err = None
    except RuntimeError as e:
        kev_err = str(e)
check("run_kev: catalog count 3 but 1 entry read -> partial recorded, and the KEV source fails",
      manifests[-1]["status"] == "partial" and manifests[-1]["records_seen"] == 3
      and manifests[-1]["records_in_scope"] == 1 and kev_err is not None and "count 3" in kev_err, str(kev_err))
check("partial is not a done status (a partial catalog is re-checked, never 'unchanged')",
      "partial" not in main.DONE_STATUSES)


# ================================================================ audit fixes (12 Nov review)
# ---------------------------------------------------------------- F6: fractions of a second kept
check("F6. iso keeps milliseconds from the source",
      main.iso(main.parse_ts("2026-10-30T14:23:34.726Z")) == "2026-10-30T14:23:34.726000Z",
      main.iso(main.parse_ts("2026-10-30T14:23:34.726Z")))
check("F6. a time without fractions prints none (watermarks and batch ids keep their form)",
      main.iso(dt.datetime(2026, 11, 1, 6, 20, tzinfo=dt.timezone.utc)) == "2026-11-01T06:20:00Z")
row, _ = main.cve_row("cves/2026/1xxx/CVE-2026-1100.json",
                      rec("CVE-2026-1100", "2026-10-30T14:23:34.726Z"), "b", "gs://x", T, T)
check("F6. a cvelist row stores the publish time with its milliseconds",
      row["date_published"] == "2026-10-30T14:23:34.726000Z", row["date_published"])

# ---------------------------------------------------------------- F1: updates of known CVEs
KNOWN = frozenset({"CVE-2026-1200", "CVE-2026-1201", "CVE-2026-1202"})
f1 = {
    "known CVE, publish date corrected to before the cohort -> admitted":
        ("CVE-2026-1200", rec("CVE-2026-1200", "2026-10-07T10:00:00Z"), "row"),
    "known CVE, PUBLISHED -> REJECTED with no datePublished -> admitted":
        ("CVE-2026-1201", rec("CVE-2026-1201", None, state="REJECTED"), "row"),
    "known CVE, normal update in scope -> admitted":
        ("CVE-2026-1202", rec("CVE-2026-1202", "2026-10-20T10:00:00Z"), "row"),
    "NEW CVE published before the cohort -> still skipped":
        ("CVE-2026-1203", rec("CVE-2026-1203", "2026-10-07T10:00:00Z"), "skip"),
    "NEW CVE rejected with no datePublished -> still skipped":
        ("CVE-2026-1204", rec("CVE-2026-1204", None, state="REJECTED"), "skip"),
}
for label, (cid, raw, expect) in f1.items():
    row, problem = main.cve_row(f"cves/2026/1xxx/{cid}.json", raw, "b", "gs://x", T, T, KNOWN)
    got = "row" if row else ("problem" if problem else "skip")
    check(f"F1. {label}", got == expect, problem or "")
row, _ = main.cve_row("cves/2026/1xxx/CVE-2026-1201.json", rec("CVE-2026-1201", None, state="REJECTED"),
                      "b", "gs://x", T, T, KNOWN)
check("F1. the rejected update keeps date_published NULL (no invented date) and its state",
      row["date_published"] is None and row["state"] == "REJECTED", str(row and row["date_published"]))

# ---------------------------------------------------------------- F2: a partial cvelist file fails
import zipfile  # noqa: E402

def delta_zip(path, members):
    with zipfile.ZipFile(path, "w") as z:
        for name, raw in members.items():
            z.writestr(name, raw)

manifests, watermarks = [], []
with tempfile.TemporaryDirectory() as tmpd:
    zpath = os.path.join(tmpd, "delta.zip")
    delta_zip(zpath, {"cves/2026/1xxx/CVE-2026-1300.json": rec("CVE-2026-1300"),
                      "cves/2026/1xxx/CVE-2026-1301.json": b"{not json"})
    release = {"tag_name": "cve_2026-11-12_1000Z",
               "assets": [{"name": "2026-11-12_delta_CVEs_at_1000Z.zip", "browser_download_url": "u"}]}

    def fetch_zip(url, what, stream_to=None, **_):
        stream_to.write(open(zpath, "rb").read())
        stream_to.flush()

    inserted = []
    with mock.patch.object(main, "latest_release", lambda: release), \
         mock.patch.object(main, "fetch", fetch_zip), \
         mock.patch.object(main, "land", lambda *a, **k: ("gs://raw/cvelist", T)), \
         mock.patch.object(main, "already_loaded", lambda *a: False), \
         mock.patch.object(main, "known_cve_ids", lambda: frozenset()), \
         mock.patch.object(main, "insert_new_only", lambda t, rows, *a, **k: inserted.append(len(rows)) or (len(rows), 0)), \
         mock.patch.object(main, "manifest", lambda **r: manifests.append(r)), \
         mock.patch.object(main, "watermark_set", lambda *a, **k: watermarks.append(a)):
        try:
            main.run_cvelist("delta")
            f2_err = None
        except RuntimeError as e:
            f2_err = str(e)
check("F2. one good + one broken record: the good one is stored, the file is recorded partial",
      inserted == [1] and manifests and manifests[-1]["status"] == "partial"
      and manifests[-1]["records_failed"] == 1, str(manifests[-1:] and manifests[-1].get("status")))
check("F2. ...and the run fails", f2_err is not None and "partial" in f2_err, str(f2_err))
check("F2. ...and the watermark (last successful check) does NOT move", watermarks == [], str(watermarks))

# ---------------------------------------------------------------- F3: NVD envelope validation
def nvd_run(pages):
    """Run run_nvd over the given response bodies; return (error, manifests, watermarks, inserted)."""
    it = iter(pages)
    mans, wms, ins = [], [], []
    with mock.patch.object(main, "watermark_get", lambda s: ("2026-11-11T06:20:00Z", None)), \
         mock.patch.object(main, "fetch", lambda *a, **k: next(it)), \
         mock.patch.object(main, "land", lambda *a, **k: ("gs://raw/nvd", T)), \
         mock.patch.object(main, "insert_new_only", lambda t, rows, *a, **k: ins.append(len(rows)) or (len(rows), 0)), \
         mock.patch.object(main, "manifest", lambda **r: mans.append(r)), \
         mock.patch.object(main, "watermark_set", lambda *a, **k: wms.append(a)), \
         mock.patch.object(main, "now", lambda: dt.datetime(2026, 11, 12, 6, 20, tzinfo=dt.timezone.utc)):
        try:
            main.run_nvd()
            return None, mans, wms, ins
        except RuntimeError as e:
            return str(e), mans, wms, ins


def vuln(i):
    return {"cve": {"id": f"CVE-2026-{1400 + i}", "vulnStatus": "Received", "published": "2026-11-10T10:00:00.000",
                    "lastModified": "2026-11-11T10:00:00.123"}}


def page(vulns, total, start=0, per=None):
    return json.dumps({"resultsPerPage": len(vulns) if per is None else per, "startIndex": start,
                       "totalResults": total, "vulnerabilities": vulns}).encode()


bad_cases = {
    "an empty object {}": [b"{}"],
    "not JSON at all": [b"<html>maintenance</html>"],
    "totalResults missing": [json.dumps({"resultsPerPage": 0, "startIndex": 0, "vulnerabilities": []}).encode()],
    "page says 2 results but holds 1": [page([vuln(0)], total=2, per=2)],
    "empty page while results remain": [page([], total=3)],
    "startIndex is not the one requested": [page([vuln(0)], total=1, start=5)],
    "second page missing (total 3, first page holds 2, second is {})": [page([vuln(0), vuln(1)], total=3), b"{}"],
}
for label, pages in bad_cases.items():
    err, mans, wms, ins = nvd_run(pages)
    check(f"F3. NVD {label}: run fails, page recorded invalid, no watermark",
          err is not None and mans and mans[-1]["status"] == "invalid" and wms == [],
          f"err={err}, status={mans[-1]['status'] if mans else None}, watermarks={len(wms)}")

err, mans, wms, ins = nvd_run([page([], total=0)])
check("F3. NVD valid empty window (totalResults 0): accepted, watermark moves",
      err is None and [m["status"] for m in mans] == ["loaded"] and len(wms) == 1, str(err))
err, mans, wms, ins = nvd_run([page([vuln(0), vuln(1)], total=3), page([vuln(2)], total=3, start=2)])
check("F3. NVD two valid pages: all 3 loaded, watermark moves once",
      err is None and ins == [2, 1] and len(wms) == 1, f"err={err}, inserted={ins}")
rows_seen = []
with mock.patch.object(main, "watermark_get", lambda s: ("2026-11-11T06:20:00Z", None)), \
     mock.patch.object(main, "fetch", lambda *a, **k: page([vuln(0)], total=1)), \
     mock.patch.object(main, "land", lambda *a, **k: ("gs://raw/nvd", T)), \
     mock.patch.object(main, "insert_new_only", lambda t, rows, *a, **k: rows_seen.extend(rows) or (len(rows), 0)), \
     mock.patch.object(main, "manifest", lambda **r: None), \
     mock.patch.object(main, "watermark_set", lambda *a, **k: None), \
     mock.patch.object(main, "now", lambda: dt.datetime(2026, 11, 12, 6, 20, tzinfo=dt.timezone.utc)):
    main.run_nvd()
check("F6. an NVD row stores last_modified with its milliseconds",
      rows_seen and rows_seen[0]["last_modified"] == "2026-11-11T10:00:00.123000Z",
      rows_seen and rows_seen[0]["last_modified"])

err, mans, wms, ins = nvd_run([page([{}], total=1)])
check("F3. NVD envelope is well formed but its record is empty ([{}]): run fails, recorded invalid, no watermark",
      err is not None and mans and mans[-1]["status"] == "invalid" and wms == [] and ins == [],
      f"err={err}, watermarks={len(wms)}")
bad_date = vuln(0)
bad_date["cve"]["lastModified"] = "not-a-date"
err, mans, wms, ins = nvd_run([page([bad_date], total=1)])
check("F3. NVD record with an unreadable lastModified: run fails, no watermark", err is not None and wms == [], str(err))
err, mans, wms, ins = nvd_run([page([vuln(0), vuln(1)], total=3), page([vuln(2)], total=3, start=2)])
check("F3. NVD last page holding fewer records than the page size (2 then 1 of 3), as NVD returns it: accepted",
      err is None and ins == [2, 1], str(err))

# ---------------------------------------------------------------- EPSS: a future score_date is refused
future = gzip.compress(b"#model_version:v2026.06.15,score_date:2026-12-25T12:55:00Z\n"
                       b"cve,epss,percentile\nCVE-2026-0001,0.1,0.5\n")
landed = []
with mock.patch.object(main, "now", lambda: dt.datetime(2026, 11, 12, 6, 20, tzinfo=dt.timezone.utc)), \
     mock.patch.object(main, "already_loaded", lambda *a: False), \
     mock.patch.object(main, "land", lambda *a, **k: landed.append(a) or ("gs://x", T)):
    try:
        main.ingest_epss(future, "current", T)
        fut_err = None
    except RuntimeError as e:
        fut_err = str(e)
check("EPSS: a file dated in the future is refused before anything is stored",
      fut_err is not None and "future" in fut_err and not landed, str(fut_err))

# ---------------------------------------------------------------- a failed run always names its error
runs = []
with mock.patch.object(main, "ensure_tables", lambda: None), \
     mock.patch.object(main, "record_run", lambda status, started, err=None: runs.append((status, err))), \
     mock.patch.dict(main.RUNNERS, {main.MODE: lambda: (_ for _ in ()).throw(TimeoutError())}), \
     mock.patch.object(main, "Lock", lambda *a: contextlib.nullcontext()):
    main.main()
check("a failed run records the exception type even when its message is empty",
      runs[-1] == ("failed", "TimeoutError: "), str(runs[-1]))

print(f"\n{sum(RESULTS)}/{len(RESULTS)} passed")
sys.exit(0 if all(RESULTS) else 1)
