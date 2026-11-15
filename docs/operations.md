# Operations

How the pipeline runs, who may do what, how code reaches production, and how to deploy it.

## Ingestion sequence (one file)
```mermaid
sequenceDiagram
    participant Src as Source
    participant Job as Extractor (Cloud Run Job)
    participant GCS as Cloud Storage
    participant BQ as BigQuery (bronze / ops)
    Job->>GCS: take the source lock (locks/<source>.lock, create-only)
    Job->>Src: download (retries; status and size checks)
    Job->>GCS: store the raw file (create-only, if_generation_match=0)
    Job->>BQ: same sha256 already processed? record "unchanged" and stop
    Job->>Job: validate and parse (bad records are counted, never silently skipped)
    Job->>BQ: insert only new rows (dedupe on the business key)
    Job->>BQ: manifest entry (file URI, sha256, counts, records_in_table, status)
    Job->>BQ: move the watermark only if the file was complete
    Job->>GCS: release the lock
```

**Outcomes per file:**

| Status | Meaning | The run |
|---|---|---|
| `loaded` | Complete and stored | Continues |
| `unchanged` | Same file seen again | Continues |
| `partial` | Some records unreadable. The good ones are stored. Gold is blocked until a later complete baseline. | Fails |
| `quarantined` | Too many unreadable records | Fails |
| `conflicts` | EPSS only: a different value for an existing `(cve_id, score_date)`. Nothing is inserted. | Fails |
| `invalid` | NVD page fails the envelope or record checks | Fails; no watermark |

A lock older than 3 hours is treated as stale.

## Run modes
The Cloud Run Job reads `MODE` from its environment. Cloud Scheduler sets it per schedule.

| Mode | What it does | Started by |
|---|---|---|
| `hourly` | CVE.org hourly delta | `vuln-hourly`, `15 * * * *` UTC |
| `cvelist_baseline` | The full CVE.org baseline | `vuln-baseline`, `40 0 * * *` UTC |
| `daily` | NVD, then KEV, then EPSS, then the Dataform workflow. If any source fails, Dataform is not started. | `vuln-daily`, `20 6 * * *` UTC |
| `nvd`, `kev`, `epss` | One source on its own | By hand |
| `epss_backfill` | Every missing EPSS day from the cohort start | By hand (initial load) |
| `epss_reprocess` | Re-parse the stored raw EPSS files | By hand |
| `dataform` | Only the Dataform workflow | By hand |

**Shared locks:**
- `hourly` and `cvelist_baseline` share the `cvelist` lock.
- `epss`, `epss_backfill` and `epss_reprocess` share the `epss` lock.

**Run a mode by hand:**
```bash
gcloud run jobs execute vuln-extractor --region=us-central1 --update-env-vars=MODE=epss_backfill
```

**Do not run manual transformations** (`infra/dataform_run.sh`) **or snapshot-sensitive verification while a daily execution is active.** They write to, or read, the same tables.

## Service accounts (least privilege, no key files)
| Account | Permissions |
|---|---|
| `extractor-sa` | Write raw files and locks to the bucket; write `bronze` and `ops`; read the `nvd-api-key` secret; start Dataform as `dataform-sa` |
| `dataform-sa` | Read `bronze`; write `silver`, `gold` and `ops`. These are dataset-level roles plus BigQuery job user, not project-wide editor. |
| `scheduler-sa` | Run the Cloud Run Job with overrides (`run.jobsExecutorWithOverrides`) |
| `build-sa` | Build, push and deploy the extractor image |

**Other rules:**
- **Dataform uses strict act-as.** Only the Dataform service agent and `extractor-sa` may act as `dataform-sa`.
- **Secrets** (`nvd-api-key`, `dataform-github-token`) live in Secret Manager. They are never in the code or the logs.

## CI/CD
**Extractor:**
- A push to `main` that changes `extractor/**` or `cloudbuild.yaml` triggers Cloud Build. It runs as `build-sa`.
- Cloud Build builds the image, tags it with the commit SHA, pushes it to Artifact Registry, and updates the Cloud Run Job with `GIT_SHA=<sha>`.
- `infra/verify_all.sh` checks that the deployed `GIT_SHA` matches `extractor/` on `main`.

**SQL:** Dataform reads `definitions/` from `main` on every run, so SQL changes need no new image.

**Process:**
1. Work on a branch.
2. Run the offline tests, plus the integration tests for extractor changes.
3. For SQL changes, run the branch with `infra/dataform_run.sh <branch>` and check `infra/show_deps.sh`.
4. Merge to `main`.

**Logging:** one structured JSON line per event, with `run_id` and `mode`. A failed run logs the exception type and the stack trace.

## Deployment outline
This is an outline of how the project was deployed, not a one-command setup.

**The scripts use fixed names.** Change them for another project:

| Name | Value |
|---|---|
| Project | `vuln-intel-warehouse` |
| Region | `us-central1` |
| Bucket | `vuln-intel-warehouse-raw` |
| Job | `vuln-extractor` |
| Dataform repository | `vuln-intel-dataform` |
| Cohort start | `2026-10-08` (job environment and `workflow_settings.yaml`) |

**Steps:**
1. `bash infra/setup_gcp.sh`: enable the APIs, and create the bucket and the datasets.
2. `bash infra/iam.sh`: the service accounts and their roles.
3. `bash infra/secret.sh`: store the NVD API key (hidden input).
4. `bash infra/registry.sh`: the Artifact Registry repository.
5. **Console:**
   - Create the Cloud Build trigger: 2nd gen, runs as `build-sa`, included files `extractor/**` and `cloudbuild.yaml`.
   - Push to `main` to build the image.
   - Create the Cloud Run Job `vuln-extractor` from that image: runs as `extractor-sa`, 1 vCPU / 4 GiB, 1-hour timeout, 1 retry. Set the environment `GOOGLE_CLOUD_PROJECT`, `REGION`, `BUCKET`, `COHORT_START` and `DATAFORM_REPO`, and `NVD_API_KEY` from the secret.
6. `bash infra/job_iam.sh`: the roles that need the job to exist.
7. **Console:** create the Dataform repository `vuln-intel-dataform`, linked to the GitHub repository (`main`). Then run `bash infra/dataform_iam.sh` for its identity and BigQuery roles.
8. **Initial loads, before the schedules.** Run them by hand with `gcloud run jobs execute`:
   - `cvelist_baseline`;
   - `nvd` (with no watermark, it starts from the cohort start);
   - `kev`;
   - `epss_backfill`.
9. **Run Dataform once** (`MODE=dataform`). Check the result with `bash infra/check_quality.sh` and `bash infra/verify_all.sh`.
10. `bash infra/scheduler.sh`: the three schedules.
