"""
Vulnerability Intelligence Warehouse: extractor (Cloud Run Job).

Modes (first CLI argument, else env MODE):
  cvelist_baseline   daily: midnight snapshot of CVE.org cvelistV5 (closes the end-of-day delta gap)
  hourly             cvelistV5 cumulative delta (since midnight UTC)
  daily              NVD (incremental by lastModified) + CISA KEV + EPSS, then Dataform
  nvd | kev | epss   one source on its own
  epss_reprocess     rebuild EPSS from the files already in the raw layer (no download)
  epss_backfill      dated EPSS files from COHORT_START to yesterday (skips files already processed)

Every run:
  - writes a started row and a finished row (succeeded/failed) to ops.ingest_runs
  - stores what it downloaded, byte for byte, in Cloud Storage (raw layer, never overwritten)
  - loads records into BigQuery bronze, only records whose content is new
    (dedupe on (cve_id, record_hash) or the source's natural key)
  - observed_at = when we first had the file (raw object time); processed_at = when it was loaded
  - writes one row per file to ops.ingest_manifest. A file counts as processed only for the
    same target table and PROCESSOR_VERSION, so a new table or parser version re-processes it.
  - advances ops.source_watermarks only after a fully successful pull
  - holds a per-source lock object in Cloud Storage so two runs never write the same source
Scope: cvelist and NVD keep CVEs whose cveMetadata.datePublished (UTC) >= COHORT_START.
KEV and EPSS are kept whole (small, and independent of when a CVE reaches the cohort).
"""
import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import logging
import os
import re
import sys
import tempfile
import time
import traceback
import uuid
import zipfile

import requests
from google.api_core.exceptions import Conflict, NotFound, PreconditionFailed
from google.cloud import bigquery, storage

# ------------------------------------------------------------------ config
PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "vuln-intel-warehouse")
REGION = os.environ.get("REGION", "us-central1")
BUCKET = os.environ.get("BUCKET", "vuln-intel-warehouse-raw")
COHORT_START = os.environ.get("COHORT_START", "2026-10-08")  # launch date minus 30 days, fixed
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()      # from Secret Manager
DATAFORM_REPO = os.environ.get("DATAFORM_REPO", "")           # empty = do not start Dataform
DATAFORM_BRANCH = os.environ.get("DATAFORM_BRANCH", "main")
DATAFORM_SA = os.environ.get("DATAFORM_SA", f"dataform-sa@{PROJECT}.iam.gserviceaccount.com")
BRONZE = os.environ.get("BRONZE_DATASET", "bronze")          # overridable for integration tests
OPS = os.environ.get("OPS_DATASET", "ops")
GIT_SHA = os.environ.get("GIT_SHA", "unknown")                # set by Cloud Build on deploy
PROCESSOR_VERSION = "2"                                       # bump to re-process stored files
NVD_OVERLAP = dt.timedelta(hours=2)                           # re-read a little of the last window
LOCK_STALE_AFTER = dt.timedelta(hours=3)

CVELIST_RELEASES = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_CURRENT = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_DATED = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"

CVE_FILE = re.compile(r"(CVE-\d{4}-\d{4,})\.json$")
SUPPORTED_DATA_VERSIONS = {"5.0", "5.1", "5.2"}

MANIFEST = f"{PROJECT}.{OPS}.ingest_manifest"
WATERMARKS = f"{PROJECT}.{OPS}.source_watermarks"
RUNS = f"{PROJECT}.{OPS}.ingest_runs"
T_CVELIST = f"{PROJECT}.{BRONZE}.cvelist_records"
T_NVD = f"{PROJECT}.{BRONZE}.nvd_records"
T_KEV = f"{PROJECT}.{BRONZE}.kev_records"
T_KEV_SNAP = f"{PROJECT}.{BRONZE}.kev_snapshots"   # full membership of every catalog version seen
T_EPSS = f"{PROJECT}.{BRONZE}.epss_scores_v2"      # whole EPSS file (v1 was filtered to the cohort)
V_EPSS_DAYS = f"{PROJECT}.{OPS}.epss_day_status"   # THE definition of a complete EPSS day (also read by Dataform)

RUN_ID = os.environ.get("CLOUD_RUN_EXECUTION") or f"local-{uuid.uuid4().hex[:8]}"
MODE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MODE", "hourly")).lower()


# ------------------------------------------------------------------ logging
class JsonFormatter(logging.Formatter):
    """One JSON object per line; Cloud Logging indexes the fields. Secrets are masked."""
    def format(self, record):
        payload = {"severity": record.levelname, "message": record.getMessage(), "mode": MODE,
                   "run_id": RUN_ID}
        payload.update(getattr(record, "fields", {}))
        line = json.dumps(payload, ensure_ascii=False, default=str)
        return line.replace(NVD_API_KEY, "***") if NVD_API_KEY else line


_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(JsonFormatter())
log = logging.getLogger("extractor")
log.addHandler(_h)
log.setLevel(logging.INFO)


def info(msg, **f):
    log.info(msg, extra={"fields": f})


def error(msg, **f):
    log.error(msg, extra={"fields": f})


def now():
    return dt.datetime.now(dt.timezone.utc)


def iso(t):
    # keeps fractions of a second when the source has them (a value with none prints none)
    return t.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def canonical_hash(obj):
    return sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def parse_ts(s):
    if s is None or s == "":
        return None
    if not isinstance(s, str):
        raise ValueError(f"timestamp is {type(s).__name__}, not text: {s!r}")
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


COHORT_START_TS = dt.datetime.fromisoformat(COHORT_START).replace(tzinfo=dt.timezone.utc)

# ------------------------------------------------------------------ clients
bq = bigquery.Client(project=PROJECT)
gcs = storage.Client(project=PROJECT).bucket(BUCKET)
http = requests.Session()
http.headers.update({"User-Agent": "vuln-intel-warehouse/1.0 (graduation project)"})


def fetch(url, what, headers=None, timeout=300, stream_to=None):
    """GET with bounded retries. 4xx (other than 429) is not retried. Secrets never logged."""
    for attempt in range(1, 4):
        try:
            with http.get(url, headers=headers or {}, timeout=timeout, stream=bool(stream_to)) as r:
                if r.status_code >= 400:
                    reason = r.headers.get("message") or r.text[:300]
                    raise RuntimeError(f"HTTP {r.status_code}: {reason}")
                if stream_to:
                    stream_to.seek(0)      # a retry must not append to a partial download
                    stream_to.truncate()
                    for chunk in r.iter_content(8 * 1024 * 1024):
                        stream_to.write(chunk)
                    stream_to.flush()
                    return None
                return r.content
        except Exception as e:  # noqa: BLE001
            msg = str(e)
            error("fetch failed", what=what, attempt=attempt, error=msg)
            if "HTTP 4" in msg and "HTTP 429" not in msg:
                raise
            if attempt == 3:
                raise
            time.sleep(15 * attempt)
    return None


# ------------------------------------------------------------------ tables
def schema(*cols):
    return [bigquery.SchemaField(n, t, mode="NULLABLE") for n, t in cols]


INGEST_COLS = [("run_id", "STRING"), ("batch_id", "STRING"), ("file_uri", "STRING"),
               ("observed_at", "TIMESTAMP"), ("processed_at", "TIMESTAMP")]
# observed_at  = when we first had the source file (raw object creation time)
# processed_at = when this row was loaded (differs from observed_at after a re-process)
TABLES = {
    MANIFEST: (schema(("run_id", "STRING"), ("mode", "STRING"), ("source", "STRING"),
                      ("batch_id", "STRING"), ("request", "STRING"), ("file_uri", "STRING"),
                      ("sha256", "STRING"), ("bytes", "INT64"), ("records_seen", "INT64"),
                      ("records_in_scope", "INT64"), ("records_new", "INT64"),
                      ("status", "STRING"), ("detail", "STRING"),
                      ("started_at", "TIMESTAMP"), ("finished_at", "TIMESTAMP"),
                      ("target", "STRING"), ("processor", "STRING"), ("records_failed", "INT64"),
                      ("records_conflicting", "INT64"), ("acquired_at", "TIMESTAMP"),
                      ("records_in_table", "INT64")),
               "finished_at", None),
    WATERMARKS: (schema(("source", "STRING"), ("watermark", "STRING"), ("last_checked_at", "TIMESTAMP"),
                        ("last_changed_at", "TIMESTAMP"), ("run_id", "STRING"),
                        ("recorded_at", "TIMESTAMP")), "recorded_at", None),
    RUNS: (schema(("run_id", "STRING"), ("mode", "STRING"), ("status", "STRING"), ("git_sha", "STRING"),
                  ("processor", "STRING"), ("error", "STRING"), ("started_at", "TIMESTAMP"),
                  ("finished_at", "TIMESTAMP"), ("recorded_at", "TIMESTAMP")), "recorded_at", None),
    T_CVELIST: (schema(("cve_id", "STRING"), ("state", "STRING"), ("data_version", "STRING"),
                       ("date_published", "TIMESTAMP"), ("date_updated", "TIMESTAMP"),
                       ("record_hash", "STRING"), ("record", "JSON"), *INGEST_COLS),
                "observed_at", ["cve_id"]),
    T_NVD: (schema(("cve_id", "STRING"), ("vuln_status", "STRING"), ("published", "TIMESTAMP"),
                   ("last_modified", "TIMESTAMP"), ("record_hash", "STRING"), ("record", "JSON"),
                   *INGEST_COLS), "observed_at", ["cve_id"]),
    T_KEV: (schema(("cve_id", "STRING"), ("catalog_version", "STRING"), ("date_released", "TIMESTAMP"),
                   ("date_added", "DATE"), ("known_ransomware_campaign_use", "STRING"),
                   ("record_hash", "STRING"), ("record", "JSON"), *INGEST_COLS), "observed_at", ["cve_id"]),
    T_KEV_SNAP: (schema(("catalog_version", "STRING"), ("cve_id", "STRING"), ("record_hash", "STRING"),
                        ("batch_id", "STRING"), ("observed_at", "TIMESTAMP"), ("processed_at", "TIMESTAMP")),
                 "observed_at", ["cve_id"]),
    # Slim on purpose (~330k rows per day): file_uri and run_id are found through batch_id in the manifest.
    T_EPSS: (schema(("cve_id", "STRING"), ("epss", "FLOAT64"), ("percentile", "FLOAT64"),
                    ("score_date", "DATE"), ("model_version", "STRING"), ("batch_id", "STRING"),
                    ("observed_at", "TIMESTAMP"), ("processed_at", "TIMESTAMP")),
             "score_date", ["cve_id"]),
}


def ensure_tables():
    """Create missing tables; add missing NULLABLE columns to existing ones (schema evolution)."""
    for table_id, (sch, part, cluster) in TABLES.items():
        t = bigquery.Table(table_id, schema=sch)
        t.time_partitioning = bigquery.TimePartitioning(field=part)
        if cluster:
            t.clustering_fields = cluster
        t = bq.create_table(t, exists_ok=True)
        have = {f.name for f in t.schema}
        missing = [f for f in sch if f.name not in have]
        if missing:
            t.schema = list(t.schema) + missing
            try:
                bq.update_table(t, ["schema"])
            except Exception:  # noqa: BLE001 - another run may have added them at the same moment
                have = {f.name for f in bq.get_table(table_id).schema}
                if any(f.name not in have for f in missing):
                    raise
            info("columns added", table=table_id, columns=[f.name for f in missing])
    ensure_views()


def epss_day_status_sql():
    """One row per EPSS score_date. complete = a successful load into the table, no conflict,
    and the table holds exactly as many rows as EVERY loaded file of that day has (and more than 0).
    file_rows is the file's row count (records_in_scope), not the rows inserted by that load:
    after a load without conflicts every key of the file is in the table with the same values,
    so equal counts mean an exact match, even when a retry inserted nothing new. If two different
    files were loaded for one day (e.g. 100 rows, then 90 of them), the table matches only one of
    them: MIN and MAX of the file sizes differ, so the day is NOT complete (fail-closed).
    The extractor's gap fill and Dataform's epss_latest both read this view: one definition."""
    return f"""
    WITH m AS (
      SELECT SAFE.PARSE_DATE('%Y-%m-%d', SPLIT(batch_id, ':')[SAFE_OFFSET(1)]) AS score_date,
        COUNTIF(status = 'loaded') AS ok_loads, COUNTIF(status = 'conflicts') AS conflict_rows,
        MAX(IF(status = 'loaded', records_in_scope, NULL)) AS file_rows,
           MIN(IF(status = 'loaded', records_in_scope, NULL)) AS file_rows_min
      FROM `{MANIFEST}` WHERE target = '{T_EPSS}' GROUP BY 1),
    t AS (SELECT score_date, COUNT(*) AS table_rows FROM `{T_EPSS}` GROUP BY 1)
    SELECT score_date, IFNULL(ok_loads, 0) AS ok_loads, IFNULL(conflict_rows, 0) AS conflict_rows,
      IFNULL(file_rows, 0) AS file_rows, IFNULL(file_rows_min, 0) AS file_rows_min, IFNULL(table_rows, 0) AS table_rows,
      (IFNULL(ok_loads, 0) > 0 AND IFNULL(conflict_rows, 0) = 0
       AND IFNULL(table_rows, 0) > 0 AND table_rows = file_rows
           AND table_rows = file_rows_min) AS complete
    FROM m FULL OUTER JOIN t USING (score_date)
    WHERE score_date IS NOT NULL"""


def ensure_views():
    """Create or refresh the views the extractor owns (definition kept in this file)."""
    v = bigquery.Table(V_EPSS_DAYS)
    v.view_query = epss_day_status_sql()
    v.description = "One row per EPSS score_date; complete = loaded, no conflict, table rows = manifest rows"
    current = bq.create_table(v, exists_ok=True)
    if current.view_query != v.view_query:
        current.view_query = v.view_query
        bq.update_table(current, ["view_query"])


def load_json_rows(table_id, rows, write="WRITE_APPEND"):
    if not rows:
        return
    cfg = bigquery.LoadJobConfig(source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                                 write_disposition=write, schema=TABLES.get(table_id, (None,))[0])
    data = "\n".join(json.dumps(r, ensure_ascii=False, default=str) for r in rows).encode()
    bq.load_table_from_file(io.BytesIO(data), table_id, job_config=cfg).result()


def insert_sql(table_id, stage, key_cols, compare_cols=()):
    """SQL used by insert_new_only (kept separate so it can be tested on its own).
    Returns (conflict_count_sql | None, insert_sql)."""
    cols = [f.name for f in TABLES[table_id][0]]
    keys = ", ".join(key_cols)
    on = " AND ".join(f"t.{c} = s.{c}" for c in key_cols)
    # One row per key inside the batch too, chosen deterministically.
    dedup = (f"SELECT * FROM `{stage}` QUALIFY ROW_NUMBER() OVER "
             f"(PARTITION BY {keys} ORDER BY TO_JSON_STRING(STRUCT({', '.join(cols)}))) = 1")
    conflict = None
    if compare_cols:
        diff = " OR ".join(f"t.{c} IS DISTINCT FROM s.{c}" for c in compare_cols)
        values = f"TO_JSON_STRING(STRUCT({', '.join(compare_cols)}))"
        # 1) key already stored with other values; 2) one key with different values inside this batch
        conflict = (f"SELECT (SELECT COUNT(*) FROM ({dedup}) s JOIN `{table_id}` t ON {on} WHERE {diff}) + "
                    f"(SELECT COUNT(*) FROM (SELECT {keys} FROM `{stage}` GROUP BY {keys} "
                    f"HAVING COUNT(DISTINCT {values}) > 1)) AS n")
    insert = (f"INSERT INTO `{table_id}` ({', '.join(cols)}) "
              f"SELECT {', '.join('s.' + c for c in cols)} FROM ({dedup}) s "
              f"WHERE NOT EXISTS (SELECT 1 FROM `{table_id}` t WHERE {on})")
    return conflict, insert


def insert_new_only(table_id, rows, key_cols, compare_cols=()):
    """Load rows to a staging table, then insert only rows whose key is not in the target.
    Returns (new_rows, conflicting_rows). Re-running with the same input inserts nothing.
    conflicting_rows: a key already stored with other compare_cols values, or one key with
    different values inside the batch. Then NOTHING from the batch is inserted; the raw file
    is kept and the caller records the conflict and fails."""
    if not rows:
        return 0, 0
    stage = f"{PROJECT}.{BRONZE}.stage_{table_id.split('.')[-1]}_{uuid.uuid4().hex[:8]}"
    sch = TABLES[table_id][0]
    bq.create_table(bigquery.Table(stage, schema=sch))
    try:
        load_json_rows(stage, rows, write="WRITE_TRUNCATE")
        conflict_q, insert_q = insert_sql(table_id, stage, key_cols, compare_cols)
        conflicts = list(bq.query(conflict_q).result())[0].n if conflict_q else 0
        if conflicts:  # nothing from a batch with conflicting values reaches the table
            return 0, conflicts
        job = bq.query(insert_q)
        job.result()
        return job.num_dml_affected_rows or 0, conflicts
    finally:
        bq.delete_table(stage, not_found_ok=True)


def rows_in_table(table_id, batch_id, where="TRUE"):
    """Lineage count: rows of table_id that carry batch_id AFTER this load. Unlike records_new (rows
    inserted by this very load), it is also right after a retry: if an earlier attempt inserted the
    rows and then failed before writing the manifest, the retry inserts 0 but the rows are counted."""
    job = bq.query(f"SELECT COUNT(*) n FROM `{table_id}` WHERE batch_id = @b AND {where}",
                   job_config=bigquery.QueryJobConfig(
                       query_parameters=[bigquery.ScalarQueryParameter("b", "STRING", batch_id)]))
    return list(job.result())[0].n


def manifest(**row):
    row.setdefault("run_id", RUN_ID)
    row.setdefault("mode", MODE)
    row.setdefault("processor", PROCESSOR_VERSION)
    row.setdefault("finished_at", iso(now()))
    load_json_rows(MANIFEST, [row])
    info("manifest", **{k: v for k, v in row.items() if k not in ("run_id", "mode")})


def watermark_get(source):
    q = (f"SELECT watermark, last_changed_at FROM `{WATERMARKS}` WHERE source = @s "
         f"ORDER BY recorded_at DESC LIMIT 1")
    rows = list(bq.query(q, job_config=bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("s", "STRING", source)])).result())
    return (rows[0].watermark, rows[0].last_changed_at) if rows else (None, None)


def watermark_set(source, value, changed):
    _, last_changed = watermark_get(source)
    load_json_rows(WATERMARKS, [{
        "source": source, "watermark": value, "last_checked_at": iso(now()),
        "last_changed_at": iso(now()) if changed else (iso(last_changed) if last_changed else None),
        "run_id": RUN_ID, "recorded_at": iso(now())}])


DONE_STATUSES = ("loaded",)  # "conflicts"/"partial" are never done: the file is re-checked every time,
                             # so it can never turn into "unchanged" and look healthy


def already_loaded(sha, target):
    """True only if this exact file was processed into this target by this processor version.
    A new target table or a new PROCESSOR_VERSION therefore re-processes stored files."""
    q = (f"SELECT COUNT(*) n FROM `{MANIFEST}` WHERE sha256 = @h AND target = @t AND processor = @p "
         f"AND status IN UNNEST(@s)")
    r = list(bq.query(q, job_config=bigquery.QueryJobConfig(query_parameters=[
        bigquery.ScalarQueryParameter("h", "STRING", sha),
        bigquery.ScalarQueryParameter("t", "STRING", target),
        bigquery.ScalarQueryParameter("p", "STRING", PROCESSOR_VERSION),
        bigquery.ArrayQueryParameter("s", "STRING", list(DONE_STATUSES))])).result())
    return r[0].n > 0


# ------------------------------------------------------------------ raw layer + lock
def land(source, name, data=None, path=None, content_type="application/octet-stream"):
    """Store bytes (or a local file) once; never overwrite an existing object.
    Returns (uri, acquired_at): acquired_at is when the object was first stored."""
    day = now().strftime("%Y-%m-%d")
    blob = gcs.blob(f"raw/{source}/ingest_date={day}/{name}")
    try:
        if path:
            blob.upload_from_filename(path, content_type=content_type, if_generation_match=0)
        else:
            blob.upload_from_string(data, content_type=content_type, if_generation_match=0)
    except PreconditionFailed:
        info("raw object already stored", uri=f"gs://{BUCKET}/{blob.name}")
    blob.reload()  # one clock for every path: the object's own creation time in Cloud Storage
    return f"gs://{BUCKET}/{blob.name}", blob.time_created


def quarantine(file_uri, reason):
    src = gcs.blob(file_uri.replace(f"gs://{BUCKET}/", ""))
    gcs.copy_blob(src, gcs, src.name.replace("raw/", "quarantine/", 1))
    error("quarantined", uri=file_uri, reason=reason)


class Lock:
    """One writer per mode: create locks/<mode>.lock only if absent (generation 0)."""
    def __init__(self, name):
        self.blob = gcs.blob(f"locks/{name}.lock")
        self.gen = None

    def __enter__(self):
        body = json.dumps({"run_id": RUN_ID, "since": iso(now())})
        try:
            self.blob.upload_from_string(body, if_generation_match=0)
        except PreconditionFailed:
            self.blob.reload()
            age = now() - self.blob.updated
            try:
                owner = json.loads(self.blob.download_as_bytes(
                    if_generation_match=self.blob.generation)).get("run_id")
            except Exception:  # noqa: BLE001 - unreadable lock: treat as someone else's
                owner = None
            if owner == RUN_ID:
                # Our own lock: a retried upload whose first attempt already succeeded,
                # or a task retry of this same execution after a crash. Safe to adopt.
                info("lock already held by this run, adopting", lock=self.blob.name, age=str(age))
                self.gen = self.blob.generation
                return self
            if age < LOCK_STALE_AFTER:
                raise RuntimeError(f"another run holds {self.blob.name} (age {age})")
            info("taking over stale lock", lock=self.blob.name, age=str(age))
            self.blob.upload_from_string(body, if_generation_match=self.blob.generation)
        self.blob.reload()
        self.gen = self.blob.generation
        return self

    def __exit__(self, *exc):
        try:
            self.blob.delete(if_generation_match=self.gen)  # only our own lock
        except (PreconditionFailed, NotFound):
            error("lock was not ours to release", lock=self.blob.name)


# ------------------------------------------------------------------ cvelistV5
def cve_row(name, raw, batch_id, file_uri, observed_at, processed_at, known=frozenset()):
    """Return (row | None, problem | None) for one CVE JSON file. Out of scope -> (None, None).
    known: CVE ids already stored. A NEW CVE is admitted only if published on or after the cohort
    start. An update of a KNOWN CVE is always admitted (even if its publish date was corrected to
    before the cohort, or it was rejected without a publish date), so the latest version reaches
    silver, which decides membership from that latest version."""
    m = CVE_FILE.search(name)
    try:
        rec = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        return None, f"{name}: unreadable ({e})"
    meta = rec.get("cveMetadata") if isinstance(rec, dict) else None
    if not isinstance(meta, dict):
        return None, f"{name}: not a CVE record"
    if rec.get("dataVersion") not in SUPPORTED_DATA_VERSIONS:
        return None, f"{name}: unsupported dataVersion {rec.get('dataVersion')}"
    if meta.get("cveId") != m.group(1):
        return None, f"{name}: cveId {meta.get('cveId')!r} does not match the file name"
    try:
        published = parse_ts(meta.get("datePublished"))
        updated = parse_ts(meta.get("dateUpdated"))
    except (TypeError, ValueError) as e:
        return None, f"{name}: bad date ({e})"
    if meta["cveId"] not in known and (published is None or published < COHORT_START_TS):
        return None, None  # a new CVE outside the cohort: out of scope, not a problem
    return {
        "cve_id": meta["cveId"], "state": meta.get("state"), "data_version": rec.get("dataVersion"),
        "date_published": iso(published) if published else None,
        "date_updated": iso(updated) if updated else None,
        "record_hash": canonical_hash(rec), "record": rec,
        "run_id": RUN_ID, "batch_id": batch_id, "file_uri": file_uri,
        "observed_at": iso(observed_at), "processed_at": iso(processed_at),
    }, None


def cve_rows_from_zip(zf, batch_id, file_uri, observed_at, processed_at, known=frozenset()):
    """Yield (row | None, problem | None) for every CVE JSON member."""
    for info_ in zf.infolist():
        if CVE_FILE.search(info_.filename):
            yield cve_row(info_.filename, zf.read(info_), batch_id, file_uri, observed_at, processed_at, known)


def known_cve_ids():
    """CVE ids already stored in bronze (about 20-30 thousand ids, one small query)."""
    return frozenset(r.cve_id for r in bq.query(f"SELECT DISTINCT cve_id FROM `{T_CVELIST}`").result())


def ingest_cvelist_zip(zip_path, source, batch_id, file_uri, file_sha, size, started, acquired):
    processed = now()
    known = known_cve_ids()
    rows, problems, seen = [], [], 0

    def take(pairs):
        nonlocal seen
        for row, problem in pairs:
            seen += 1
            if problem:
                problems.append(problem)
            if row:
                rows.append(row)

    with zipfile.ZipFile(zip_path) as outer:
        inner_zip = next((n for n in outer.namelist() if n.endswith(".zip")), None)
        if inner_zip:  # baseline: ZIP inside a ZIP
            with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
                with outer.open(inner_zip) as src:
                    while chunk := src.read(16 * 1024 * 1024):
                        tmp.write(chunk)
                tmp.flush()
                with zipfile.ZipFile(tmp.name) as inner:
                    take(cve_rows_from_zip(inner, batch_id, file_uri, acquired, processed, known))
        else:  # hourly delta: CVE files directly
            take(cve_rows_from_zip(outer, batch_id, file_uri, acquired, processed, known))
    common = dict(source=source, batch_id=batch_id, file_uri=file_uri, sha256=file_sha, bytes=size,
                  records_seen=seen, records_failed=len(problems), target=T_CVELIST,
                  acquired_at=iso(acquired), started_at=iso(started))
    if problems and len(problems) > max(10, seen // 100):
        quarantine(file_uri, f"{len(problems)} bad records, e.g. {problems[:3]}")
        manifest(**common, records_in_scope=0, records_new=0, status="quarantined",
                 detail="; ".join(problems[:5]))
        raise RuntimeError("too many bad records; file quarantined")
    new, _ = insert_new_only(T_CVELIST, rows, ["cve_id", "record_hash"])
    manifest(**common, records_in_scope=len(rows), records_new=new,
             records_in_table=rows_in_table(T_CVELIST, batch_id),
             status="partial" if problems else "loaded", detail="; ".join(problems[:5]))
    if problems:
        error("cvelist records skipped", count=len(problems), examples=problems[:5])
        # the good records are stored, but the file is not complete: fail, so run_cvelist does
        # not record a successful check; gold stays blocked until a later complete baseline
        raise RuntimeError(f"cvelist file partial: {len(problems)} records skipped, e.g. {problems[:3]}")
    return new


def latest_release():
    return json.loads(fetch(f"{CVELIST_RELEASES}/latest", "cvelist latest release"))


def run_cvelist(kind):
    started = now()
    rel = latest_release()
    tag = rel["tag_name"]
    asset = next(a for a in rel["assets"]
                 if ("all_CVEs_at_midnight" in a["name"]) == (kind == "baseline") and a["name"].endswith(".zip"))
    batch_id = f"{tag}:{asset['name']}"
    with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
        fetch(asset["browser_download_url"], f"cvelist {kind} {asset['name']}", stream_to=tmp)
        with open(tmp.name, "rb") as f:
            file_sha = hashlib.file_digest(f, "sha256").hexdigest()
        size = os.path.getsize(tmp.name)
        file_uri, acquired = land("cvelist", f"{tag}__{asset['name']}", path=tmp.name,
                                  content_type="application/zip")
        if already_loaded(file_sha, T_CVELIST):
            manifest(source="cvelist", batch_id=batch_id, file_uri=file_uri, sha256=file_sha, bytes=size,
                     records_seen=0, records_in_scope=0, records_new=0, status="unchanged", target=T_CVELIST,
                     detail="same file already processed", acquired_at=iso(acquired), started_at=iso(started))
            watermark_set("cvelist", tag, changed=False)
            return 0
        new = ingest_cvelist_zip(tmp.name, "cvelist", batch_id, file_uri, file_sha, size, started, acquired)
    watermark_set("cvelist", tag, changed=new > 0)
    return new


# ------------------------------------------------------------------ NVD
def nvd_page_checked(d, idx):
    """Validate one NVD response page requested at startIndex=idx.
    Returns (vulnerabilities, total, per_page) or raises ValueError. An empty page is valid only
    when NVD says there is nothing left (totalResults == idx, e.g. 0 results)."""
    if not isinstance(d, dict):
        raise ValueError(f"NVD response is {type(d).__name__}, not an object")
    vulns = d.get("vulnerabilities")
    fields = {k: d.get(k) for k in ("totalResults", "resultsPerPage", "startIndex")}
    if not isinstance(vulns, list):
        raise ValueError("NVD response has no 'vulnerabilities' list")
    for k, v in fields.items():
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ValueError(f"NVD response field {k} is {v!r}")
    total, per_page, start = fields["totalResults"], fields["resultsPerPage"], fields["startIndex"]
    if start != idx:
        raise ValueError(f"NVD startIndex {start}, requested {idx}")
    if len(vulns) != per_page:
        raise ValueError(f"NVD page says resultsPerPage {per_page} but holds {len(vulns)}")
    if idx < total and per_page == 0:
        raise ValueError(f"NVD page is empty at {idx} of {total}")
    if idx + per_page > total:
        raise ValueError(f"NVD page goes past totalResults ({idx}+{per_page} > {total})")
    for i, v in enumerate(vulns):  # a well-formed envelope can still hold a broken record
        c = v.get("cve") if isinstance(v, dict) else None
        if not isinstance(c, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(c.get("id"))) \
                or not isinstance(c.get("vulnStatus"), str):
            raise ValueError(f"NVD record {idx + i} is not a readable CVE record")
        try:
            if parse_ts(c.get("published")) is None or parse_ts(c.get("lastModified")) is None:
                raise ValueError("missing date")
        except (TypeError, ValueError) as e:
            raise ValueError(f"NVD record {idx + i} ({c.get('id')}): bad published/lastModified ({e})") from e
    return vulns, total, per_page


def run_nvd():
    """Incremental by lastModified: fixed window end, short overlap, watermark after full success."""
    started = now()
    wm, _ = watermark_get("nvd")
    window_end = now().replace(microsecond=0)
    window_start = (parse_ts(wm) - NVD_OVERLAP) if wm else COHORT_START_TS
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    pause = 0.8 if NVD_API_KEY else 6.5
    total_new = 0
    chunk_start = window_start
    while chunk_start < window_end:  # NVD accepts at most 120 days per request
        chunk_end = min(chunk_start + dt.timedelta(days=119), window_end)
        idx, page = 0, 0
        while True:
            q = (f"lastModStartDate={chunk_start.strftime('%Y-%m-%dT%H:%M:%S.000Z')}"
                 f"&lastModEndDate={chunk_end.strftime('%Y-%m-%dT%H:%M:%S.000Z')}"
                 f"&resultsPerPage=2000&startIndex={idx}")
            body = fetch(f"{NVD_API}?{q}", f"nvd page {page}", headers=headers)
            batch_id = f"nvd:{iso(chunk_start)}..{iso(chunk_end)}:p{page}"
            file_uri, acquired = land(
                "nvd", f"{chunk_start:%Y%m%dT%H%M%S}_{chunk_end:%Y%m%dT%H%M%S}_p{page:03d}_{sha256(body)[:12]}.json",
                data=body, content_type="application/json")
            processed = now()
            try:  # parsed after landing, so even an unreadable page is kept in raw
                vulns, total, per_page = nvd_page_checked(json.loads(body), idx)
            except ValueError as e:  # the raw page is kept; nothing is loaded; no watermark
                manifest(source="nvd", batch_id=batch_id, request=q, file_uri=file_uri, sha256=sha256(body),
                         bytes=len(body), records_seen=0, records_in_scope=0, records_new=0, status="invalid",
                         target=T_NVD, detail=str(e), acquired_at=iso(acquired), started_at=iso(started))
                raise RuntimeError(f"NVD page {page} invalid: {e}") from e
            rows = []
            for v in vulns:
                c = v.get("cve", {})
                pub = parse_ts(c.get("published"))
                if pub is None or pub < COHORT_START_TS - dt.timedelta(days=2):
                    continue  # out of scope (cohort is by cvelist datePublished; small buffer)
                rows.append({"cve_id": c.get("id"), "vuln_status": c.get("vulnStatus"),
                             "published": iso(pub), "last_modified": iso(parse_ts(c.get("lastModified"))),
                             "record_hash": canonical_hash(c), "record": c, "run_id": RUN_ID,
                             "batch_id": batch_id, "file_uri": file_uri, "observed_at": iso(acquired),
                             "processed_at": iso(processed)})
            new, _ = insert_new_only(T_NVD, rows, ["cve_id", "record_hash"])
            total_new += new
            manifest(source="nvd", batch_id=batch_id, request=q, file_uri=file_uri, sha256=sha256(body),
                     bytes=len(body), records_seen=len(vulns),
                     records_in_scope=len(rows), records_new=new, status="loaded", target=T_NVD,
                     records_in_table=rows_in_table(T_NVD, batch_id),
                     acquired_at=iso(acquired), started_at=iso(started))
            idx += per_page
            page += 1
            time.sleep(pause)
            if idx >= total:  # nvd_page_checked guarantees progress while idx < total
                break
        chunk_start = chunk_end
    watermark_set("nvd", iso(window_end), changed=total_new > 0)  # only after every page succeeded
    return total_new


# ------------------------------------------------------------------ KEV
def kev_rows(d, file_sha, acquired, processed):
    """Rows for kev_records (one per entry) and kev_snapshots (full membership of this catalog)."""
    version = d.get("catalogVersion")
    batch_id = f"kev:{version}:{file_sha[:12]}"
    released = iso(parse_ts(d.get("dateReleased"))) if d.get("dateReleased") else None
    records, members = [], []
    for v in d.get("vulnerabilities", []):
        h = canonical_hash(v)
        records.append({"cve_id": v.get("cveID"), "catalog_version": version, "date_released": released,
                        "date_added": v.get("dateAdded"),
                        "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse"),
                        "record_hash": h, "record": v, "run_id": RUN_ID, "batch_id": batch_id,
                        "observed_at": iso(acquired), "processed_at": iso(processed)})
        members.append({"catalog_version": version, "cve_id": v.get("cveID"), "record_hash": h,
                        "batch_id": batch_id, "observed_at": iso(acquired), "processed_at": iso(processed)})
    return batch_id, records, members


def run_kev():
    started = now()
    body = fetch(KEV_URL, "kev catalog")
    file_sha = sha256(body)
    d = json.loads(body)
    version = d.get("catalogVersion")
    file_uri, acquired = land("kev", f"kev_{version}_{file_sha[:12]}.json", data=body,
                              content_type="application/json")
    if already_loaded(file_sha, T_KEV):
        manifest(source="kev", batch_id=f"kev:{version}:{file_sha[:12]}", file_uri=file_uri, sha256=file_sha,
                 bytes=len(body), records_seen=d.get("count"), records_in_scope=0, records_new=0,
                 status="unchanged", target=T_KEV, detail="catalog unchanged", acquired_at=iso(acquired),
                 started_at=iso(started))
        watermark_set("kev", version, changed=False)
        return 0
    batch_id, records, members = kev_rows(d, file_sha, acquired, now())
    for r in records:
        r["file_uri"] = file_uri
    published = d.get("count")
    count_ok = published == len(records)
    new, _ = insert_new_only(T_KEV, records, ["cve_id", "record_hash"])
    insert_new_only(T_KEV_SNAP, members, ["batch_id", "cve_id"])
    manifest(source="kev", batch_id=batch_id, file_uri=file_uri, sha256=file_sha, bytes=len(body),
             records_seen=published, records_in_scope=len(records), records_new=new,
             records_in_table=rows_in_table(T_KEV, batch_id),
             records_failed=0 if count_ok else abs((published or 0) - len(records)),
             status="loaded" if count_ok else "partial", target=T_KEV,
             detail=f"catalog {version}: CISA count {published}, entries read {len(records)}",
             acquired_at=iso(acquired), started_at=iso(started))
    if not count_ok:
        raise RuntimeError(f"KEV catalog {version}: CISA count {published} but {len(records)} entries read; "
                           "not used (the last complete catalog stays in use)")
    watermark_set("kev", version, changed=new > 0)
    return new


# ------------------------------------------------------------------ EPSS
def parse_epss(body):
    """Return (model_version, score_date 'YYYY-MM-DD', csv text without the comment line)."""
    text = gzip.decompress(body).decode("utf-8")
    first, _, rest = text.partition("\n")
    meta = dict(kv.split(":", 1) for kv in first.lstrip("#").split(",") if ":" in kv)
    model, score_ts = meta.get("model_version"), meta.get("score_date")
    if not score_ts or not rest.startswith("cve,epss,percentile"):
        raise RuntimeError(f"unexpected EPSS header: {first[:120]} / {rest[:40]}")
    return model, score_ts[:10], rest


def ingest_epss(body, label, started, file_uri=None, acquired=None, expected_date=None):
    """Load one whole EPSS file. With file_uri, the file is re-processed from the raw layer.
    With expected_date, a file whose score_date is another day is refused (nothing is loaded).
    Value conflicts are loaded nowhere, recorded in the manifest, and fail the run, so a report
    is never published on top of them."""
    file_sha = sha256(body)
    model, score_date, rest = parse_epss(body)
    if expected_date and score_date != expected_date:
        raise RuntimeError(f"EPSS file for {expected_date} has score_date {score_date}")
    if dt.date.fromisoformat(score_date) > now().date() + dt.timedelta(days=1):
        raise RuntimeError(f"EPSS file has score_date {score_date}, in the future")
    batch_id = f"epss:{score_date}:{file_sha[:12]}"
    if already_loaded(file_sha, T_EPSS):
        manifest(source="epss", batch_id=batch_id, file_uri=file_uri, sha256=file_sha, bytes=len(body),
                 records_seen=0, records_in_scope=0, records_new=0, status="unchanged", target=T_EPSS,
                 detail=f"{label}; already processed", started_at=iso(started))
        return score_date, 0
    if file_uri is None:
        file_uri, acquired = land("epss", f"epss_{score_date}_{file_sha[:12]}.csv.gz", data=body,
                                  content_type="application/gzip")
    processed = now()
    rows = [{"cve_id": r["cve"], "epss": float(r["epss"]), "percentile": float(r["percentile"]),
             "score_date": score_date, "model_version": model, "batch_id": batch_id,
             "observed_at": iso(acquired), "processed_at": iso(processed)}
            for r in csv.DictReader(io.StringIO(rest))]
    new, conflicts = insert_new_only(T_EPSS, rows, ["cve_id", "score_date"],
                                     compare_cols=["epss", "percentile", "model_version"])
    if conflicts:
        error("EPSS values differ from stored values for the same day; stored values kept",
              score_date=score_date, conflicts=conflicts, file_uri=file_uri)
    manifest(source="epss", batch_id=batch_id, file_uri=file_uri, sha256=file_sha, bytes=len(body),
             records_seen=len(rows), records_in_scope=len(rows), records_new=new,
             records_in_table=rows_in_table(T_EPSS, batch_id, f"score_date = '{score_date}'"),
             records_conflicting=conflicts, status="conflicts" if conflicts else "loaded", target=T_EPSS,
             detail=f"{label}; model {model}", acquired_at=iso(acquired), started_at=iso(started))
    if conflicts:
        raise RuntimeError(f"EPSS {score_date}: {conflicts} values differ from stored ones; not published")
    return score_date, new


def epss_gap_days(current_date):
    """Days from COHORT_START to the day before current_date that are not complete,
    by the shared definition in ops.epss_day_status (a hole behind a later day is found)."""
    q = f"""
    SELECT FORMAT_DATE('%Y-%m-%d', d) AS day
    FROM UNNEST(GENERATE_DATE_ARRAY(@start, DATE_SUB(@c, INTERVAL 1 DAY))) AS d
    LEFT JOIN `{V_EPSS_DAYS}` s ON s.score_date = d
    WHERE NOT IFNULL(s.complete, FALSE)
    ORDER BY d"""
    cfg = bigquery.QueryJobConfig(query_parameters=[
        bigquery.ScalarQueryParameter("start", "DATE", COHORT_START_TS.date().isoformat()),
        bigquery.ScalarQueryParameter("c", "DATE", current_date)])
    return [r.day for r in bq.query(q, job_config=cfg).result()]


def run_epss():
    """Load the current EPSS file, then fill any day missed since the last one we hold
    (EPSS published late, a run failed, ...). 'Current already processed' is not proof of
    completeness, so gaps are checked on every run."""
    started = now()
    score_date, new = ingest_epss(fetch(EPSS_CURRENT, "epss current"), "current", started)
    failed = []
    for day in epss_gap_days(score_date):
        try:
            _, n = ingest_epss(fetch(EPSS_DATED.format(day=day), f"epss {day}"), f"gap fill {day}",
                               started, expected_date=day)
            new += n
            info("EPSS gap filled", score_date=day, rows=n)
        except Exception as e:  # noqa: BLE001 - try every missing day, fail at the end
            failed.append(day)
            manifest(source="epss", batch_id=f"epss:{day}", status="failed", target=T_EPSS,
                     detail=f"gap fill: {str(e)[:280]}", started_at=iso(started))
    if failed:
        raise RuntimeError(f"EPSS gap fill incomplete: missing days {failed}")
    # Final check, same definition, including the current day itself ('unchanged' is not proof).
    next_day = (dt.date.fromisoformat(score_date) + dt.timedelta(days=1)).isoformat()
    still_missing = epss_gap_days(next_day)
    if still_missing:
        raise RuntimeError(f"EPSS days still incomplete after this run: {still_missing}")
    watermark_set("epss", score_date, changed=new > 0)
    return new


def run_epss_reprocess():
    """Rebuild the EPSS table from files already stored in the raw layer (replay, no download).
    observed_at keeps the time the file was first stored; processed_at is now."""
    started, total, failed = now(), 0, []
    for blob in gcs.list_blobs(prefix="raw/epss/"):
        try:
            _, new = ingest_epss(blob.download_as_bytes(), f"reprocess {blob.name}", started,
                                 file_uri=f"gs://{BUCKET}/{blob.name}", acquired=blob.time_created)
            total += new
        except Exception as e:  # noqa: BLE001 - try every file, fail at the end
            failed.append(blob.name)
            manifest(source="epss", file_uri=f"gs://{BUCKET}/{blob.name}", status="failed", target=T_EPSS,
                     detail=str(e)[:300], started_at=iso(started))
    if failed:
        raise RuntimeError(f"EPSS re-process incomplete: {len(failed)} files failed, e.g. {failed[:3]}")
    return total


def run_epss_backfill():
    """Dated EPSS files from COHORT_START to yesterday. Files already processed are skipped."""
    started, total, failed = now(), 0, []
    day, today = COHORT_START_TS.date(), now().date()
    while day < today:
        try:
            _, new = ingest_epss(fetch(EPSS_DATED.format(day=day.isoformat()), f"epss {day}"),
                                 f"backfill {day}", started, expected_date=day.isoformat())
            total += new
        except Exception as e:  # noqa: BLE001 - try every day, fail at the end
            failed.append(day.isoformat())
            manifest(source="epss", batch_id=f"epss:{day}", status="failed", target=T_EPSS,
                     detail=str(e)[:300], started_at=iso(started))
        day += dt.timedelta(days=1)
    if failed:
        raise RuntimeError(f"EPSS backfill incomplete: missing days {failed}")
    return total


# ------------------------------------------------------------------ Dataform
def run_dataform():
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    s = AuthorizedSession(creds)
    base = (f"https://dataform.googleapis.com/v1beta1/projects/{PROJECT}/locations/{REGION}"
            f"/repositories/{DATAFORM_REPO}")
    comp = s.post(f"{base}/compilationResults", json={"gitCommitish": DATAFORM_BRANCH}, timeout=120)
    comp.raise_for_status()
    comp = comp.json()
    if comp.get("compilationErrors"):
        raise RuntimeError(f"Dataform compilation errors: {comp['compilationErrors'][:3]}")
    commit = comp.get("resolvedGitCommitSha")  # the exact SQL version, not just "main"
    inv = s.post(f"{base}/workflowInvocations", timeout=120, json={
        "compilationResult": comp["name"],
        "invocationConfig": {"serviceAccount": DATAFORM_SA}})  # strict act-as: run as dataform-sa
    if inv.status_code >= 400:
        raise RuntimeError(f"Dataform invocation refused: HTTP {inv.status_code} {inv.text[:300]}")
    name = inv.json()["name"]
    info("dataform started", invocation=name, commit=commit, service_account=DATAFORM_SA)
    for _ in range(180):
        time.sleep(10)
        state = s.get(f"https://dataform.googleapis.com/v1beta1/{name}", timeout=60).json().get("state")
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            info("dataform finished", invocation=name, state=state)
            if state != "SUCCEEDED":
                raise RuntimeError(f"Dataform workflow {state}")
            return {"invocation": name, "commit": commit}
    raise RuntimeError("Dataform workflow timed out")


# ------------------------------------------------------------------ main
def run_daily():
    results, failed = {}, []
    for name, fn in (("nvd", run_nvd), ("kev", run_kev), ("epss", run_epss)):
        try:
            with Lock(name):
                results[name] = fn()
        except Exception as e:  # noqa: BLE001 - other sources still run; report fails at the end
            failed.append(name)
            error("source failed", source=name, error=str(e)[:500])
    info("daily pulls finished", new_rows=results, failed=failed)
    if failed:
        raise RuntimeError(f"sources failed: {failed}; report not published")
    if DATAFORM_REPO:
        run_dataform()
    else:
        info("DATAFORM_REPO not set: transformations not started")
    return sum(results.values())


def run_dataform_only():
    """Run the Dataform workflow on its own (to test the automated path and its identity)."""
    if not DATAFORM_REPO:
        raise RuntimeError("DATAFORM_REPO is not set")
    run_dataform()
    return 0


RUNNERS = {
    "cvelist_baseline": lambda: run_cvelist("baseline"),
    "hourly": lambda: run_cvelist("delta"),
    "daily": run_daily,
    "nvd": run_nvd,
    "kev": run_kev,
    "epss": run_epss,
    "epss_reprocess": run_epss_reprocess,
    "epss_backfill": run_epss_backfill,
    "dataform": lambda: run_dataform_only(),
}
# Modes that write the same tables share one lock.
LOCK_FOR = {"hourly": "cvelist", "cvelist_baseline": "cvelist",
            "epss_reprocess": "epss", "epss_backfill": "epss"}


def record_run(status, started, err=None):
    """ops.ingest_runs: one row when a run starts and one when it ends, even if nothing was downloaded."""
    try:
        load_json_rows(RUNS, [{"run_id": RUN_ID, "mode": MODE, "status": status, "git_sha": GIT_SHA,
                               "processor": PROCESSOR_VERSION, "error": (err or "")[:1000] or None,
                               "started_at": iso(started),
                               "finished_at": None if status == "started" else iso(now()),
                               "recorded_at": iso(now())}])
    except Exception as e:  # noqa: BLE001 - bookkeeping must never hide the real result
        error("could not write ops.ingest_runs", error=str(e)[:300])


def main():
    if MODE not in RUNNERS:
        error("unknown mode", known=list(RUNNERS))
        return 2
    started = now()
    try:
        ensure_tables()
    except Exception as e:  # noqa: BLE001
        error("run failed", error=f"ensure_tables: {e}"[:1000])
        return 1
    record_run("started", started)
    try:
        if MODE == "daily":
            new = RUNNERS[MODE]()  # takes one lock per source inside
        else:
            with Lock(LOCK_FOR.get(MODE, MODE)):
                new = RUNNERS[MODE]()
        info("run finished", new_rows=new)
        record_run("succeeded", started)
        return 0
    except Exception as e:  # noqa: BLE001
        # the exception type is always written: some errors have an empty message
        # (the cvelist_baseline failure of 11 Nov was recorded with no message at all)
        reason = f"{type(e).__name__}: {e}"
        error("run failed", error=reason[:1000], traceback=traceback.format_exc()[-4000:])
        record_run("failed", started, reason)
        return 1


if __name__ == "__main__":
    sys.exit(main())
