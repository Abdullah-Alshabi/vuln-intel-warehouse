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

    def __init__(self, name):
        self.name = name
        self.generation = None
        self.updated = None

    def upload_from_string(self, data, if_generation_match=None, **_):
        cur = self.store.get(self.name)
        cur_gen = cur[0] if cur else 0
        if if_generation_match is not None and if_generation_match != cur_gen:
            raise PreconditionFailed(self.name)
        data = data.encode() if isinstance(data, str) else data
        self.store[self.name] = (cur_gen + 1, data, main.now())

    def reload(self):
        gen, _, upd = self.store[self.name]
        self.generation, self.updated = gen, upd

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
    "unsupported dataVersion": (json.dumps({"dataVersion": "4.0", "cveMetadata": {"cveId": "CVE-2026-1006"}}).encode(),
                                "problem"),
}
names = {"in scope": "CVE-2026-1000", "published before cohort": "CVE-2026-1001",
         "rejected before publish (no datePublished)": "CVE-2026-1002",
         "cveId does not match file name": "CVE-2026-1003", "cveMetadata is not an object": "CVE-2026-1004",
         "bad date": "CVE-2026-1005", "unsupported dataVersion": "CVE-2026-1006"}
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

print(f"\n{sum(RESULTS)}/{len(RESULTS)} passed")
sys.exit(0 if all(RESULTS) else 1)
