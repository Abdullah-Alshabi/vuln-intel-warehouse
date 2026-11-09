// Tables written by the extractor (Cloud Run Job). Dataform only reads them.
["cvelist_records", "nvd_records", "kev_records", "kev_snapshots", "epss_scores_v2"].forEach((name) =>
  declare({ schema: "bronze", name })
);
["ingest_manifest", "ingest_runs", "source_watermarks"].forEach((name) =>
  declare({ schema: "ops", name })
);
