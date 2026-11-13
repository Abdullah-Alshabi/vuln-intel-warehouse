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
