CREATE TABLE IF NOT EXISTS repo_snapshots (
  id TEXT PRIMARY KEY,
  owner_sub TEXT NOT NULL,
  source TEXT NOT NULL,
  full_name TEXT NOT NULL,
  html_url TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  visibility TEXT NOT NULL DEFAULT 'private',
  default_branch TEXT NOT NULL DEFAULT 'main',
  primary_language TEXT NOT NULL DEFAULT 'Unknown',
  languages_json TEXT NOT NULL DEFAULT '[]',
  frameworks_json TEXT NOT NULL DEFAULT '[]',
  ecosystems_json TEXT NOT NULL DEFAULT '[]',
  runtimes_json TEXT NOT NULL DEFAULT '[]',
  manifests_json TEXT NOT NULL DEFAULT '[]',
  docker_images_json TEXT NOT NULL DEFAULT '[]',
  dependencies_json TEXT NOT NULL DEFAULT '[]',
  key_files_json TEXT NOT NULL DEFAULT '[]',
  findings_count INTEGER NOT NULL DEFAULT 0,
  critical_count INTEGER NOT NULL DEFAULT 0,
  high_count INTEGER NOT NULL DEFAULT 0,
  last_pushed_at TEXT,
  scanned_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_repo_snapshots_owner_sub ON repo_snapshots (owner_sub);

CREATE TABLE IF NOT EXISTS vulnerability_findings (
  id TEXT PRIMARY KEY,
  owner_sub TEXT NOT NULL,
  repo_full_name TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  aliases_json TEXT NOT NULL DEFAULT '[]',
  title TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'dependency',
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  installed_version TEXT NOT NULL,
  fixed_version TEXT NOT NULL DEFAULT '',
  manifest_path TEXT NOT NULL DEFAULT '',
  reference_url TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  detected_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_owner_sub ON vulnerability_findings (owner_sub);
CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_repo ON vulnerability_findings (owner_sub, repo_full_name);

CREATE TABLE IF NOT EXISTS advisory_checks (
  id TEXT PRIMARY KEY,
  owner_sub TEXT NOT NULL,
  query_input TEXT NOT NULL,
  parsed_summary TEXT NOT NULL,
  parsed_json TEXT NOT NULL,
  total_repos INTEGER NOT NULL DEFAULT 0,
  affected_count INTEGER NOT NULL DEFAULT 0,
  needs_review_count INTEGER NOT NULL DEFAULT 0,
  cleared_count INTEGER NOT NULL DEFAULT 0,
  results_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_advisory_checks_owner_sub ON advisory_checks (owner_sub, created_at DESC);

CREATE TABLE IF NOT EXISTS scan_runs (
  id TEXT PRIMARY KEY,
  owner_sub TEXT NOT NULL,
  mode TEXT NOT NULL,
  repos_scanned INTEGER NOT NULL DEFAULT 0,
  dependencies_indexed INTEGER NOT NULL DEFAULT 0,
  findings_detected INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_owner_sub ON scan_runs (owner_sub, created_at DESC);
