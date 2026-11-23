CREATE TABLE IF NOT EXISTS threat_watch_seen (
  id TEXT PRIMARY KEY,
  owner_sub TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  identifiers_json TEXT NOT NULL DEFAULT '[]',
  started_at TEXT NOT NULL DEFAULT '',
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_threat_watch_seen_owner_sub ON threat_watch_seen (owner_sub);

CREATE TABLE IF NOT EXISTS threat_watch_runs (
  id TEXT PRIMARY KEY,
  owner_sub TEXT NOT NULL,
  trigger_source TEXT NOT NULL,
  feed_items_checked INTEGER NOT NULL DEFAULT 0,
  new_incidents_count INTEGER NOT NULL DEFAULT 0,
  repos_scanned INTEGER NOT NULL DEFAULT 0,
  affected_repos_count INTEGER NOT NULL DEFAULT 0,
  patch_plans_json TEXT NOT NULL DEFAULT '[]',
  summary TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_threat_watch_runs_owner_sub ON threat_watch_runs (owner_sub, created_at DESC);
