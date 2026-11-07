"""
Vulnerability Intelligence Warehouse: extractor (Cloud Run Job).

Modes (first CLI argument, else env MODE):
  cvelist_baseline   once: midnight snapshot of CVE.org cvelistV5 (recovery: run again)
  hourly             cvelistV5 cumulative delta (since midnight UTC)
  daily              NVD (incremental by lastModified) + CISA KEV + EPSS, then Dataform
  nvd | kev | epss   one source on its own
  epss_backfill      EPSS files for the EPSS_BACKFILL_DAYS days before today

Every run:
  - stores what it downloaded, byte for byte, in Cloud Storage (raw layer, never overwritten)
  - loads only in-scope records into BigQuery bronze, and only records whose content is new
    (dedupe on (cve_id, record_hash) or the source's natural key)
  - writes one row per file to ops.ingest_manifest and advances ops.source_watermarks
    only after a fully successful pull
  - holds a per-mode lock object in Cloud Storage so two runs never write the same source
Scope: CVEs whose cveMetadata.datePublished (UTC) >= COHORT_START.
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
EPSS_BACKFILL_DAYS = int(os.environ.get("EPSS_BACKFILL_DAYS", "30"))
NVD_OVERLAP = dt.timedelta(hours=2)                           # re-read a little of the last window
LOCK_STALE_AFTER = dt.timedelta(hours=3)

CVELIST_RELEASES = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_CURRENT = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_DATED = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"

CVE_FILE = re.compile(r"(CVE-\d{4}-\d{4,})\.json$")
SUPPORTED_DATA_VERSIONS = {"5.0", "5.1", "5.2"}

MANIFEST = f"{PROJECT}.ops.ingest_manifest"
WATERMARKS = f"{PROJECT}.ops.source_watermarks"
T_CVELIST = f"{PROJECT}.bronze.cvelist_records"
T_NVD = f"{PROJECT}.bronze.nvd_records"
T_KEV = f"{PROJECT}.bronze.kev_records"
T_EPSS = f"{PROJECT}.bronze.epss_scores"

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
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def canonical_hash(obj):
    return sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def parse_ts(s):
    if not s:
        return None
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
            r = http.get(url, headers=headers or {}, timeout=timeout, stream=bool(stream_to))
            if r.status_code >= 400:
                reason = r.headers.get("message") or r.text[:300]
                raise RuntimeError(f"HTTP {r.status_code}: {reason}")
            if stream_to:
                for chunk in r.iter_content(8 * 1024 * 1024):
                    stream_to.write(chunk)
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
               ("observed_at", "TIMESTAMP")]
TABLES = {
    MANIFEST: (schema(("run_id", "STRING"), ("mode", "STRING"), ("source", "STRING"),
                      ("batch_id", "STRING"), ("request", "STRING"), ("file_uri", "STRING"),
                      ("sha256", "STRING"), ("bytes", "INT64"), ("records_seen", "INT64"),
                      ("records_in_scope", "INT64"), ("records_new", "INT64"),
                      ("status", "STRING"), ("detail", "STRING"),
                      ("started_at", "TIMESTAMP"), ("finished_at", "TIMESTAMP")), "finished_at", None),
    WATERMARKS: (schema(("source", "STRING"), ("watermark", "STRING"), ("last_checked_at", "TIMESTAMP"),
                        ("last_changed_at", "TIMESTAMP"), ("run_id", "STRING"),
                        ("recorded_at", "TIMESTAMP")), "recorded_at", None),
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
    T_EPSS: (schema(("cve_id", "STRING"), ("epss", "FLOAT64"), ("percentile", "FLOAT64"),
                    ("score_date", "DATE"), ("model_version", "STRING"), *INGEST_COLS),
             "score_date", ["cve_id"]),
}


def ensure_tables():
    for table_id, (sch, part, cluster) in TABLES.items():
        t = bigquery.Table(table_id, schema=sch)
        t.time_partitioning = bigquery.TimePartitioning(field=part)
        if cluster:
            t.clustering_fields = cluster
        bq.create_table(t, exists_ok=True)


def load_json_rows(table_id, rows, write="WRITE_APPEND"):
    if not rows:
        return
    cfg = bigquery.LoadJobConfig(source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                                 write_disposition=write, schema=TABLES.get(table_id, (None,))[0])
    data = "\n".join(json.dumps(r, ensure_ascii=False, default=str) for r in rows).encode()
    bq.load_table_from_file(io.BytesIO(data), table_id, job_config=cfg).result()


def insert_new_only(table_id, rows, key_cols):
    """Load rows to a staging table, then insert only rows whose key is not in the target.
    Returns how many rows were new. Re-running with the same input inserts nothing."""
    if not rows:
        return 0
    stage = f"{PROJECT}.bronze.stage_{table_id.split('.')[-1]}_{uuid.uuid4().hex[:8]}"
    sch = TABLES[table_id][0]
    bq.create_table(bigquery.Table(stage, schema=sch))
    try:
        load_json_rows(stage, rows, write="WRITE_TRUNCATE")
        on = " AND ".join(f"t.{c} = s.{c}" for c in key_cols)
        cols = ", ".join(f.name for f in sch)
        q = (f"INSERT INTO `{table_id}` ({cols}) SELECT {', '.join('s.' + f.name for f in sch)} "
             f"FROM `{stage}` s WHERE NOT EXISTS (SELECT 1 FROM `{table_id}` t WHERE {on})")
        job = bq.query(q)
        job.result()
        return job.num_dml_affected_rows or 0
    finally:
        bq.delete_table(stage, not_found_ok=True)


def manifest(**row):
    row.setdefault("run_id", RUN_ID)
    row.setdefault("mode", MODE)
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


def already_loaded(sha):
    q = f"SELECT COUNT(*) n FROM `{MANIFEST}` WHERE sha256 = @h AND status IN ('loaded', 'unchanged')"
    r = list(bq.query(q, job_config=bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("h", "STRING", sha)])).result())
    return r[0].n > 0


# ------------------------------------------------------------------ raw layer + lock
def land(source, name, data=None, path=None, content_type="application/octet-stream"):
    """Store bytes (or a local file) once; never overwrite an existing object."""
    day = now().strftime("%Y-%m-%d")
    blob = gcs.blob(f"raw/{source}/ingest_date={day}/{name}")
    try:
        if path:
            blob.upload_from_filename(path, content_type=content_type, if_generation_match=0)
        else:
            blob.upload_from_string(data, content_type=content_type, if_generation_match=0)
    except PreconditionFailed:
        info("raw object already stored", uri=f"gs://{BUCKET}/{blob.name}")
    return f"gs://{BUCKET}/{blob.name}"


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
def cve_rows_from_zip(zf, batch_id, file_uri, observed_at):
    """Yield (row | None, problem | None) for every CVE JSON member, in scope only."""
    for info_ in zf.infolist():
        m = CVE_FILE.search(info_.filename)
        if not m:
            continue
        try:
            rec = json.loads(zf.read(info_))
        except Exception as e:  # noqa: BLE001
            yield None, f"{info_.filename}: unreadable ({e})"
            continue
        if not isinstance(rec, dict) or "cveMetadata" not in rec:
            yield None, f"{info_.filename}: not a CVE record"
            continue
        if rec.get("dataVersion") not in SUPPORTED_DATA_VERSIONS:
            yield None, f"{info_.filename}: unsupported dataVersion {rec.get('dataVersion')}"
            continue
        meta = rec["cveMetadata"]
        published = parse_ts(meta.get("datePublished"))
        if published is None or published < COHORT_START_TS:
            # Out of scope, not a problem. A CVE rejected before it was ever published has no
            # datePublished and never belongs to the cohort; one published in scope and rejected
            # later keeps its datePublished and stays, so the rejection is recorded.
            yield None, None
            continue
        yield {
            "cve_id": meta.get("cveId") or m.group(1), "state": meta.get("state"),
            "data_version": rec.get("dataVersion"), "date_published": iso(published) if published else None,
            "date_updated": iso(parse_ts(meta.get("dateUpdated"))) if meta.get("dateUpdated") else None,
            "record_hash": canonical_hash(rec), "record": rec,
            "run_id": RUN_ID, "batch_id": batch_id, "file_uri": file_uri, "observed_at": iso(observed_at),
        }, None


def ingest_cvelist_zip(zip_path, source, batch_id, file_uri, file_sha, size, started):
    observed = now()
    rows, problems, seen = [], [], 0
    with zipfile.ZipFile(zip_path) as outer:
        names = outer.namelist()
        inner_zip = next((n for n in names if n.endswith(".zip")), None)
        if inner_zip:  # baseline: ZIP inside a ZIP
            with tempfile.NamedTemporaryFile(suffix=".zip") as tmp:
                with outer.open(inner_zip) as src:
                    while chunk := src.read(16 * 1024 * 1024):
                        tmp.write(chunk)
                tmp.flush()
                with zipfile.ZipFile(tmp.name) as inner:
                    for row, problem in cve_rows_from_zip(inner, batch_id, file_uri, observed):
                        seen += 1
                        if problem:
                            problems.append(problem)
                        if row:
                            rows.append(row)
        else:  # hourly delta: CVE files directly
            for row, problem in cve_rows_from_zip(outer, batch_id, file_uri, observed):
                seen += 1
                if problem:
                    problems.append(problem)
                if row:
                    rows.append(row)
    if problems and len(problems) > max(10, seen // 100):
        quarantine(file_uri, f"{len(problems)} bad records, e.g. {problems[:3]}")
        manifest(source=source, batch_id=batch_id, file_uri=file_uri, sha256=file_sha, bytes=size,
                 records_seen=seen, records_in_scope=0, records_new=0, status="quarantined",
                 detail="; ".join(problems[:5]), started_at=iso(started))
        raise RuntimeError("too many bad records; file quarantined")
    new = insert_new_only(T_CVELIST, rows, ["cve_id", "record_hash"])
    manifest(source=source, batch_id=batch_id, file_uri=file_uri, sha256=file_sha, bytes=size,
             records_seen=seen, records_in_scope=len(rows), records_new=new, status="loaded",
             detail=("; ".join(problems[:5]) if problems else ""), started_at=iso(started))
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
        tmp.flush()
        with open(tmp.name, "rb") as f:
            file_sha = hashlib.file_digest(f, "sha256").hexdigest()
        size = os.path.getsize(tmp.name)
        file_uri = land("cvelist", f"{tag}__{asset['name']}", path=tmp.name, content_type="application/zip")
        if already_loaded(file_sha):
            manifest(source="cvelist", batch_id=batch_id, file_uri=file_uri, sha256=file_sha, bytes=size,
                     records_seen=0, records_in_scope=0, records_new=0, status="unchanged",
                     detail="same file already processed", started_at=iso(started))
            watermark_set("cvelist", tag, changed=False)
            return 0
        new = ingest_cvelist_zip(tmp.name, "cvelist", batch_id, file_uri, file_sha, size, started)
    watermark_set("cvelist", tag, changed=new > 0)
    return new


# ------------------------------------------------------------------ NVD
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
            d = json.loads(body)
            batch_id = f"nvd:{iso(chunk_start)}..{iso(chunk_end)}:p{page}"
            file_uri = land("nvd", f"{chunk_start:%Y%m%dT%H%M%S}_{chunk_end:%Y%m%dT%H%M%S}_p{page:03d}_{sha256(body)[:12]}.json",
                            data=body, content_type="application/json")
            observed = now()
            rows = []
            for v in d.get("vulnerabilities", []):
                c = v.get("cve", {})
                pub = parse_ts(c.get("published"))
                if pub is None or pub < COHORT_START_TS - dt.timedelta(days=2):
                    continue  # out of scope (cohort is by cvelist datePublished; small buffer)
                rows.append({"cve_id": c.get("id"), "vuln_status": c.get("vulnStatus"),
                             "published": iso(pub), "last_modified": iso(parse_ts(c.get("lastModified"))),
                             "record_hash": canonical_hash(c), "record": c, "run_id": RUN_ID,
                             "batch_id": batch_id, "file_uri": file_uri, "observed_at": iso(observed)})
            new = insert_new_only(T_NVD, rows, ["cve_id", "record_hash"])
            total_new += new
            manifest(source="nvd", batch_id=batch_id, request=q, file_uri=file_uri, sha256=sha256(body),
                     bytes=len(body), records_seen=len(d.get("vulnerabilities", [])),
                     records_in_scope=len(rows), records_new=new, status="loaded", started_at=iso(started))
            idx += d.get("resultsPerPage", 0)
            page += 1
            time.sleep(pause)
            if idx >= d.get("totalResults", 0) or d.get("resultsPerPage", 0) == 0:
                break
        chunk_start = chunk_end
    watermark_set("nvd", iso(window_end), changed=total_new > 0)  # only after every page succeeded
    return total_new


# ------------------------------------------------------------------ KEV
def run_kev():
    started = now()
    body = fetch(KEV_URL, "kev catalog")
    file_sha = sha256(body)
    d = json.loads(body)
    version = d.get("catalogVersion")
    file_uri = land("kev", f"kev_{version}_{file_sha[:12]}.json", data=body, content_type="application/json")
    if already_loaded(file_sha):
        manifest(source="kev", batch_id=f"kev:{version}", file_uri=file_uri, sha256=file_sha, bytes=len(body),
                 records_seen=d.get("count"), records_in_scope=0, records_new=0, status="unchanged",
                 detail="catalog unchanged", started_at=iso(started))
        watermark_set("kev", version, changed=False)
        return 0
    observed = now()
    rows = [{"cve_id": v.get("cveID"), "catalog_version": version,
             "date_released": iso(parse_ts(d.get("dateReleased"))) if d.get("dateReleased") else None,
             "date_added": v.get("dateAdded"), "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse"),
             "record_hash": canonical_hash(v), "record": v, "run_id": RUN_ID, "batch_id": f"kev:{version}",
             "file_uri": file_uri, "observed_at": iso(observed)} for v in d.get("vulnerabilities", [])]
    new = insert_new_only(T_KEV, rows, ["cve_id", "record_hash"])
    manifest(source="kev", batch_id=f"kev:{version}", file_uri=file_uri, sha256=file_sha, bytes=len(body),
             records_seen=len(rows), records_in_scope=len(rows), records_new=new, status="loaded",
             started_at=iso(started))
    watermark_set("kev", version, changed=new > 0)
    return new


# ------------------------------------------------------------------ EPSS
def cohort_ids():
    q = f"SELECT DISTINCT cve_id FROM `{T_CVELIST}`"
    return {r.cve_id for r in bq.query(q).result()}


def ingest_epss(body, label, started, ids):
    file_sha = sha256(body)
    text = gzip.decompress(body).decode("utf-8")
    first, _, rest = text.partition("\n")
    meta = dict(kv.split(":", 1) for kv in first.lstrip("#").split(",") if ":" in kv)
    model, score_ts = meta.get("model_version"), meta.get("score_date")
    if not score_ts or not rest.startswith("cve,epss,percentile"):
        raise RuntimeError(f"unexpected EPSS header: {first[:120]} / {rest[:40]}")
    score_date = score_ts[:10]
    file_uri = land("epss", f"epss_{score_date}_{file_sha[:12]}.csv.gz", data=body, content_type="application/gzip")
    if already_loaded(file_sha):
        manifest(source="epss", batch_id=f"epss:{score_date}", file_uri=file_uri, sha256=file_sha,
                 bytes=len(body), records_seen=0, records_in_scope=0, records_new=0, status="unchanged",
                 detail=label, started_at=iso(started))
        return score_date, 0
    observed = now()
    rows, seen = [], 0
    for r in csv.DictReader(io.StringIO(rest)):
        seen += 1
        if r["cve"] in ids:
            rows.append({"cve_id": r["cve"], "epss": float(r["epss"]), "percentile": float(r["percentile"]),
                         "score_date": score_date, "model_version": model, "run_id": RUN_ID,
                         "batch_id": f"epss:{score_date}", "file_uri": file_uri, "observed_at": iso(observed)})
    new = insert_new_only(T_EPSS, rows, ["cve_id", "score_date"])
    manifest(source="epss", batch_id=f"epss:{score_date}", file_uri=file_uri, sha256=file_sha, bytes=len(body),
             records_seen=seen, records_in_scope=len(rows), records_new=new, status="loaded",
             detail=f"{label}; model {model}", started_at=iso(started))
    return score_date, new


def run_epss():
    started = now()
    score_date, new = ingest_epss(fetch(EPSS_CURRENT, "epss current"), "current", started, cohort_ids())
    watermark_set("epss", score_date, changed=new > 0)
    return new


def run_epss_backfill():
    started, ids, total = now(), cohort_ids(), 0
    for d in range(EPSS_BACKFILL_DAYS, 0, -1):
        day = (now() - dt.timedelta(days=d)).strftime("%Y-%m-%d")
        try:
            _, new = ingest_epss(fetch(EPSS_DATED.format(day=day), f"epss {day}"), f"backfill {day}", started, ids)
            total += new
        except Exception as e:  # noqa: BLE001 - one missing day must not stop the backfill
            manifest(source="epss", batch_id=f"epss:{day}", status="failed", detail=str(e)[:300],
                     started_at=iso(started))
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
    inv = s.post(f"{base}/workflowInvocations", json={"compilationResult": comp["name"]}, timeout=120)
    inv.raise_for_status()
    name = inv.json()["name"]
    info("dataform started", invocation=name)
    for _ in range(180):
        time.sleep(10)
        state = s.get(f"https://dataform.googleapis.com/v1beta1/{name}", timeout=60).json().get("state")
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            info("dataform finished", invocation=name, state=state)
            if state != "SUCCEEDED":
                raise RuntimeError(f"Dataform workflow {state}")
            return
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


RUNNERS = {
    "cvelist_baseline": lambda: run_cvelist("baseline"),
    "hourly": lambda: run_cvelist("delta"),
    "daily": run_daily,
    "nvd": run_nvd,
    "kev": run_kev,
    "epss": run_epss,
    "epss_backfill": run_epss_backfill,
}


def main():
    if MODE not in RUNNERS:
        error("unknown mode", known=list(RUNNERS))
        return 2
    try:
        ensure_tables()
        lock_name = "cvelist" if MODE in ("hourly", "cvelist_baseline") else MODE
        if MODE == "daily":
            new = RUNNERS[MODE]()  # takes one lock per source inside
        else:
            with Lock(lock_name):
                new = RUNNERS[MODE]()
        info("run finished", new_rows=new)
        return 0
    except Exception as e:  # noqa: BLE001
        error("run failed", error=str(e)[:1000])
        return 1


if __name__ == "__main__":
    sys.exit(main())
