# Vulnerability Intelligence Warehouse

An automated data warehouse on Google Cloud that brings together four public
vulnerability sources and publishes one reproducible daily review report.

**For each CVE in scope, the report shows:** its review priority, the piece of
evidence that raised or lowered that priority, and who published that evidence.
Any report the system published can be rebuilt later from the same raw batches,
with the same code and rule versions, and checked against the published fingerprint.

## Sources

| Source | What it adds | Pulled |
|---|---|---|
| [CVE.org cvelistV5](https://github.com/CVEProject/cvelistV5) | Official CVE records (CNA data, CISA-ADP enrichment) | Hourly delta |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | NIST analysis status, NVD CVSS, CPE configurations | Daily, incremental by `lastModified` |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed exploitation, ransomware use | Daily snapshot |
| [FIRST EPSS](https://www.first.org/epss/) | Probability of exploitation in the next 30 days (model output) | Daily file |

## Architecture

```
Cloud Scheduler ──▶ Cloud Run Job (Python extractor)
                      ├─ raw files, unchanged ─▶ Cloud Storage
                      └─ in-scope records ─────▶ BigQuery bronze
                    Dataform (SQL + assertions, executed by BigQuery)
                      bronze ─▶ silver (observations, history) ─▶ gold (daily report)
                    Looker Studio reads gold
ops: ingest_manifest · source_watermarks · report_runs
CI/CD: GitHub ─▶ Cloud Build ─▶ Artifact Registry ─▶ Cloud Run Job
```

## Scope (MVP)

- CVEs with `cveMetadata.datePublished` (UTC) in the 30 days before launch, plus every CVE published after it.
- Region: `us-central1`. Project: `vuln-intel-warehouse`.

Status: work in progress (graduation project, Tuwaiq Academy, Data Engineering on Google Cloud).
