# Data dictionary: gold layer

This page describes the two objects the dashboard reads:

- **`gold.cve_current`** (table): one row per published CVE in scope, with the latest state.
- **`gold.coverage_summary`** (view): one row of summary numbers computed from `gold.cve_current`.

The same descriptions are stored on the BigQuery columns (Dataform `columns:`), so they also show in the BigQuery console. Whether they carry over to a Looker Studio data source is checked when the data source is created; field descriptions can also be set in Looker Studio itself.

## Scope and refresh

| Item | Value |
|---|---|
| CVEs in scope | CVE.org state `PUBLISHED`, publish date on or after the cohort start (`2026-10-08`). REJECTED CVEs are excluded. |
| Grain | One row per `cve_id`. Checked by the `uniqueKey` assertion and by `assert_candidate_matches_scope`. |
| Refresh | Every Dataform run (daily job at 06:20 UTC, plus manual runs). |
| Publishing gate | `gold.cve_current_candidate` is built first. `gold.cve_current` is rebuilt only if every check passes: the silver checks, the candidate's own checks, `assert_sources_ready` and `assert_candidate_matches_scope`. If any check fails, `gold.cve_current` is **not** rebuilt and keeps the last good result. This was tested on 2026-11-11 with a deliberately failing assertion. |
| "Current" means | The latest state our pipeline collected successfully. It is not a guarantee that the row matches the sources at every moment. |

## Reading NULL

NULL is never 0, and never "low" or "safe". What it means depends on the column (each table below has a "NULL means" column):

- **Value not available:** e.g. `cvss_score`, `epss_score`.
- **Does not apply:** e.g. `kev_date_added` for a CVE that is not in KEV.
- **No gap found:** `missing_data` is NULL when none of its three checks found a gap.

- **No CVSS** → `cvss_score` is NULL, not 0.
- **No EPSS** → `epss_score` is NULL. We never use an older day's score.
- **Not in KEV** → `is_kev` is FALSE. FALSE only means the CVE is not in the catalog. It does not prove the CVE is not exploited.

`missing_data` tracks three gaps only (no CVSS, no EPSS, no NVD record), so they can be filtered and counted. It does not check every column.

## Priority rule (project policy)

The rules are checked **in order**, and the first match wins:

| Priority | Condition | Source |
|---|---|---|
| **P1** | In the latest valid CISA KEV catalog | CISA KEV |
| **P2** | Not P1, and EPSS ≥ 0.10 (10%) | FIRST EPSS |
| **P3** | Not P1/P2, and CVSS base score ≥ 9.0 | CVE.org / NVD (by the CVSS rule) |
| **Other** | Everything else, including CVEs with no CVSS and no EPSS | none |

This is a **general review priority**, not a remediation priority for any specific organisation. **Other does not mean safe.** When both CVSS and EPSS are missing, `priority_reason` ends with "Not assessed as safe."

## `gold.cve_current`

Example values are from **CVE-2026-123158** (OpenSSH, published 2026-11-05), as built on 2026-11-11.

### Identity and description (source: CVE.org cvelist, via `silver.cve_latest`)

| Column | Type | Meaning | Allowed values / unit | NULL means | Example |
|---|---|---|---|---|---|
| `cve_id` | STRING | CVE identifier | `CVE-YYYY-N…` | never NULL | `CVE-2026-123158` |
| `title` | STRING | Short title written by the CNA | free text | the CNA gave no title | (see BigQuery) |
| `description` | STRING | English description written by the CNA | free text | the CNA gave no English description | `sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, …` |
| `published_at` | TIMESTAMP | When CVE.org published the CVE | UTC | never NULL | `2026-11-05 15:46:26` |
| `assigner` | STRING | Short name of the CNA that owns the record | CNA short name | not given | `mitre` |
| `first_listed_vendor` | STRING | Vendor of the **first** affected product listed (not all of them) | free text | no value was extracted from the first affected entry (the entry may exist without this field) | `OpenBSD` |
| `first_listed_product` | STRING | **First** affected product listed (not all of them) | free text | no value was extracted from the first affected entry (the entry may exist without this field) | `OpenSSH` |

### CVSS (source: CVE.org and NVD, via `silver.cvss_selected`)

One score is chosen per CVE by the project rule:

1. **Version:** 4.0, then 3.1, then 3.0, then 2.0.
2. **Provider, within the version:**
   1. the CNA via cvelist
   2. CISA-ADP via cvelist
   3. NVD-authored
   4. another ADP via cvelist
   5. a non-NVD score read via NVD (the fallback)
3. **Scenario:** the GENERAL (or unspecified) scenario first.
4. **Score:** the highest base score among candidates that are still tied.

This is a project policy, not proof that one provider is more accurate.

| Column | Type | Meaning | Allowed values / unit | NULL means | Example |
|---|---|---|---|---|---|
| `cvss_score` | FLOAT64 | Chosen CVSS base score | 0–10 | no valid score in the data we hold (never 0) | `8.1` |
| `cvss_version` | STRING | Version of the chosen score | `4.0`, `3.1`, `3.0`, `2.0` (not comparable across versions) | no score | `3.1` |
| `cvss_severity` | STRING | Severity text given by the source with this score | e.g. `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | the source gave none, or no score | `HIGH` |
| `cvss_provider` | STRING | Who wrote the score | CNA/ADP short name (or CVE.org orgId), or NVD's source field | no score | `mitre` |
| `cvss_provider_role` | STRING | Role of the provider | `CNA`, `ADP`, `NVD`, `non-NVD` | no score | `CNA` |
| `cvss_via` | STRING | Where we read the score | `cvelist`, `nvd` | no score | `cvelist` |
| `cvss_vector` | STRING | CVSS vector of the chosen score | CVSS vector string | no score | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| `cvss_is_fallback` | BOOL | TRUE if the score is a non-NVD score read via NVD (last option) | TRUE / FALSE | no score | `false` |
| `cvss_selection_reason` | STRING | Why this score was chosen | plain text | no score | `v3.1 from CNA (mitre) via cvelist; GENERAL/default scenario` |

### KEV (source: CISA KEV, via `silver.kev_current`)

| Column | Type | Meaning | Allowed values / unit | NULL means | Example |
|---|---|---|---|---|---|
| `is_kev` | BOOL | In the latest **valid** KEV catalog (one whose entry count matched CISA's own count) | TRUE / FALSE | never NULL | `true` |
| `kev_date_added` | DATE | When CISA added the CVE to KEV | date | not in KEV | `2026-11-09` |
| `kev_ransomware_use` | STRING | CISA's `knownRansomwareCampaignUse` | `Known`, `Unknown` (`Unknown` does not mean it was not used in ransomware) | not in KEV | `Unknown` |
| `kev_catalog_version` | STRING | KEV catalog version used for **every** row (one catalog per update) | CISA version string | never NULL (checked) | `2026.11.10` |
| `kev_checked_at` | TIMESTAMP | When we last saw that catalog, same for every row | UTC | never NULL (checked) | `2026-11-11 06:21:47` |

`kev_date_added` is per CVE. `kev_catalog_version` and `kev_checked_at` describe the catalog as a whole.

### EPSS (source: FIRST EPSS, via `silver.epss_latest`)

| Column | Type | Meaning | Allowed values / unit | NULL means | Example |
|---|---|---|---|---|---|
| `epss_score` | FLOAT64 | Estimated probability that exploitation activity for this CVE is observed in the 30 days after `epss_score_date`. Not the probability that a specific system is compromised | 0–1 (show as %) | no score for this CVE in that file, e.g. a CVE newer than the file (never 0, never an older score) | `0.16501` (16.5%) |
| `epss_percentile` | FLOAT64 | Share of all scored CVEs with a lower or equal EPSS | 0–1 | same as `epss_score` | `0.97016` |
| `epss_score_date` | DATE | Date of the EPSS file used, same for every row. It does **not** mean this CVE had a score in it | date (latest **complete** day in `ops.epss_day_status`) | never NULL (checked) | `2026-11-10` |
| `epss_model_version` | STRING | EPSS model version of that file | e.g. `v2026.06.15` | not given in the file | `v2026.06.15` |

### NVD (source: NIST NVD API, via `silver.nvd_latest`)

| Column | Type | Meaning | Allowed values / unit | NULL means | Example |
|---|---|---|---|---|---|
| `nvd_status` | STRING | NVD's `vulnStatus` from the latest NVD record we loaded | e.g. `Received`, `Awaiting Analysis`, `Undergoing Analysis`, `Analyzed`, `Modified`, `Deferred` | no record in the NVD data we loaded | `Analyzed` |

### Lineage (for tracing a row back to bronze)

| Column | Type | Meaning | NULL means | Example |
|---|---|---|---|---|
| `cve_record_hash` | STRING | Fingerprint of the CVE.org record version used (`bronze.cvelist_records`) | never NULL | `63e377a482c4…` |
| `nvd_record_hash` | STRING | Fingerprint of the NVD record version used (`bronze.nvd_records`) | not in NVD data | `7c9672f1b740…` |
| `cvss_record_hash` | STRING | Fingerprint of the record version the chosen score belongs to | no score | `63e377a482c4…` |

To follow one CVE through every layer, run `bash infra/trace_cve.sh <CVE-ID>`.

### Priority and status

| Column | Type | Meaning | Allowed values | NULL means | Example |
|---|---|---|---|---|---|
| `priority` | STRING | General review priority (rule above) | `P1`, `P2`, `P3`, `Other` | never NULL | `P1` |
| `priority_reason` | STRING | Plain-English reason, with the values and sources used | text | never NULL | `In CISA KEV (added 2026-11-09)` |
| `missing_data` | STRING | What is missing for this CVE | any of `no CVSS`, `no EPSS`, `not in NVD data`, joined by `; ` | none of the three tracked gaps (CVSS, EPSS, NVD record); not a sign that every column is filled | NULL |
| `updated_at` | TIMESTAMP | When this published result was built: the start time of the statement that built `gold.cve_current`. The same for every row | UTC | never NULL | `2026-11-11 16:55:31` |

More `priority_reason` examples:

- P2: `Not in KEV; EPSS 12.3% is at or above the project threshold of 10%`
- P3: `Not in KEV; EPSS 0.45% is below 10%; CVSS 9.8 (v3.1, CNA example) is at or above 9.0`
- Other: `Not in KEV; CVSS 6.5 (v3.1, CNA example) is below 9.0; EPSS unavailable`
- Other with nothing known: `Not in KEV; CVSS unavailable; EPSS unavailable. Not assessed as safe.`

(The CVE values in these examples are illustrative; the wording is exactly what the SQL produces.)

## `gold.coverage_summary`

This is one row, computed from `gold.cve_current` only, so its numbers always match the dashboard table. Percentages are rounded to 1 decimal place.

| Column | Meaning | Example (2026-11-11) |
|---|---|---|
| `cves_in_scope` | Published CVEs in the result | `20606` |
| `in_kev` | CVEs in the latest valid KEV catalog | `27` |
| `p1` / `p2` / `p3` / `other` | CVEs per priority (they add up to `cves_in_scope`) | `27` / `3` / `1813` / `18763` |
| `pct_without_cvss` | % of CVEs for which no valid CVSS score was selected from the data used in the selection (not proof that no score exists anywhere) | `5.2` |
| `pct_without_epss` | % of CVEs with no score in the chosen EPSS file | `10.8` |
| `pct_not_in_nvd` | % of CVEs with no record in the NVD data we loaded | `0.9` |
| `pct_nvd_deferred` | % of CVEs whose NVD status is `Deferred` | `36.8` |
| `updated_at` | When the published result was built (UTC) | `2026-11-11 16:55:31` |
| `epss_score_date` | Date of the EPSS file used | `2026-11-10` |
| `kev_catalog_version` | KEV catalog version used | `2026.11.10` |

## Known limitations

- **Gold shows the current state only.** Raw files and bronze keep earlier versions, but historical priority reporting ("what was the priority on date X") is not provided. A historical as-of view, SCD2 and replay are deferred.
- **Vendor and product are the first ones listed** in the CVE record. They are not normalised, and they are not the full affected list.
- **CVSS versions are not comparable.** A v4.0 8.1 and a v3.1 8.1 are not the same measurement.
- **KEV FALSE does not prove a CVE is not exploited.** The **EPSS threshold of 10%** and the **CVSS threshold of 9.0** are project choices, not industry standards.
