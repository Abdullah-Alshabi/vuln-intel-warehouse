// Tables written by the extractor (Cloud Run Job). Dataform only reads them.
["cvelist_records", "nvd_records", "kev_records", "kev_snapshots", "epss_scores_v2"].forEach((name) =>
  declare({ schema: "bronze", name })
);
// epss_day_status is a view the extractor creates: the single definition of a complete EPSS day.
["ingest_manifest", "ingest_runs", "source_watermarks", "epss_day_status"].forEach((name) =>
  declare({ schema: "ops", name })
);
