# Verification

`bash infra/verify_all.sh [--baseline]` checks the whole project read-only:

1. **Offline tests.**
2. **Deployed code and schedules.**
3. **Quality rules.**
4. **Warehouse consistency** (manifest → bronze → silver → gold).
5. **The stored raw files compared with every layer.**
6. **The publishing gate in the compiled Dataform graph.**

## Result
**ALL CHECKS PASSED** on **13 November 2026** for the deployed extractor **`f65f2a5`**. Gold was built by the scheduled daily run at 2026-11-13 06:25 UTC. This result is tied to that run and that version; it is not a general guarantee for all data or for future runs.

The verification suite passed all implemented checks for the tested production state. It validates stored source files, selected raw-to-warehouse comparisons, transformation rules, and operational controls. It does not guarantee complete historical source delivery or establish the correctness of upstream source data.

## Test levels
| Level | What it covers | Result |
|---|---|---|
| **Offline unit tests** (`tests/test_offline.py`) | Parsing and scope (including updates to known CVEs), locks, interrupted downloads, conflicts, partial files, NVD envelope and record validation, EPSS gap filling and completeness, timestamp precision, error logging | **59 / 59** |
| **Integration on real BigQuery** (`tests/run_integration.sh`) | Re-processing raw EPSS files; idempotency; a processor-version bump; conflicts; duplicates inside a batch; KEV membership A → B → A; EPSS gap days; **failure injection** (the INSERT succeeds, the manifest write fails, and the retry completes with lineage intact); two different files for one EPSS day (not complete) | **28 / 28**. Uses throwaway `test_` datasets and a bucket, deleted at the end. |
| **Quality rules** (`infra/check_quality.sh`) | 22 rules on production bronze and ops | **22 / 22** |
| **Warehouse consistency** (`tests/verify_warehouse.py`) | **Manifest → bronze:** rows per batch, files and sha256. **Bronze → silver:** re-derived. **Silver → gold:** values, priority, reason and `missing_data` recomputed; summary recount. **Operations:** freshness and failed runs. | **26 / 26** |
| **Raw against the layers** (`tests/verify_raw.py`) | The stored files gold was built from, compared value by value with bronze, silver and gold | **28 / 28** (with `--baseline`) |
| **Publishing gate** | The compiled Dataform dependencies (`infra/show_deps.sh`), plus a deliberate failing assertion | Gold skipped and the last result kept |

## End-to-end run of 13 Nov 2026 (deployed `f65f2a5`)
- **EPSS, file of 12 Nov:** file 405,484 rows = bronze 405,484, with 0 values different. All 21,393 gold rows match the file, and are blank exactly where the file has no score.
- **KEV catalog 2026.11.10:** 1,779 entries = CISA's count = the membership stored in bronze. The 27 gold CVEs in KEV match the file.
- **NVD:** 3 recent pages; every in-scope record is stored with the same fingerprint.
- **CVE.org full baseline of 13 Nov (662 MB):**
  - the sha256 matches the manifest;
  - **21,416 records in scope or already known**, all stored in bronze;
  - none missing from silver, and none older in silver than in the file;
  - every PUBLISHED record whose silver version is this file's version is in gold.
  - Gold holds **21,393** rows after the scope and state filtering (REJECTED and out-of-scope versions are excluded).
- **EPSS completeness:** every day from 8 Oct is complete. The audit of 12 Nov measured 13,816,312 rows for 8 Oct–11 Nov.

## Review findings
An AI-assisted code review identified six issues. Each was fixed, covered by a test that fails on the old code, and re-verified in production:

| # | Issue | Fix |
|---|---|---|
| **F1** | An update to a known CVE whose publish date moved before the cohort (or that was rejected without a date) was dropped | Updates to known CVEs are always stored, and silver decides membership |
| **F2** | A partial CVE.org file moved the watermark | The run fails, and gold is blocked until a later complete baseline |
| **F3** | An empty or invalid NVD response was treated as an empty window | The envelope and each record are validated, and the watermark does not move |
| **F4** | A retry after a lost manifest write left an EPSS day incomplete | Completeness compares the table with every loaded file; `records_in_table` keeps lineage after a retry |
| **F5** | 0.09999 was shown as "10.0% is below 10%" | The text is truncated in NUMERIC |
| **F6** | Fractions of a second were dropped from timestamps | Fractions are kept from now on; silver reads the precise values from the stored JSON |

## Limits
- **Independence.** Silver is re-derived with the same documented rules. `tests/verify_raw.py` reuses the extractor's `cve_row()` and `canonical_hash()`. Some comparisons therefore test **consistency between stages**, not a fully independent check of the parser: an error shared by both paths would pass.
- **Point in time.** The bronze-to-silver comparison approximates the bronze state when silver was built:
  - it keeps rows with `COALESCE(processed_at, observed_at)` up to silver's `last_modified_time`;
  - this is an approximation for the check, not an exact historical reconstruction;
  - historical report reproduction is out of scope.
- **EPSS completeness** is a row count (every loaded file of the day = the table). It holds **together with** the uniqueness and conflict checks; a count match alone does not prove that values match.

## Known incident: cvelist_baseline, 11 Nov 2026 00:40 UTC
The run failed twice, the attempt and its retry, with an empty error message (execution `vuln-extractor-jtwjn`).

The failure cause remains unknown. No remaining data gap was found against the tested 12 and 13 November baselines. These checks do not rule out earlier ingestion delays or missed intermediate source versions.

Since 13 Nov, every failed run logs the exception type and the stack trace.
