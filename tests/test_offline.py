"""Offline unit tests for extractor/main.py: no network, no Google Cloud.
Google client libraries are replaced with stubs, so this runs anywhere:
    python3 tests/test_offline.py
"""
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
check("epss_day_status: complete needs a load, no conflict, and table rows = manifest rows (> 0)",
      all(x in main.epss_day_status_sql() for x in ("ok_loads", "conflict_rows", "table_rows = loaded_rows")))

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

print(f"\n{sum(RESULTS)}/{len(RESULTS)} passed")
sys.exit(0 if all(RESULTS) else 1)
