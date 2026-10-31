-- Unified asset graph — Postgres deployment (newtask.md C1, section 3.1)
--
-- Same shape as the SQLite runtime schema (src/db/database.ts migration 007)
-- with the Postgres-specific graph abstractions the spec calls for:
--   * ltree adjacency path per node for subtree queries
--   * GIST index on the path for traversal
--   * BIGSERIAL event log with the same dedupe unique index
--
-- Bitemporal: valid_from/valid_to = assertion interval (valid_to NULL = open);
-- observed_at = last observation. Nothing is ever deleted, only closed.
-- UID scheme: '<type>:' || substr(sha256(type || '|' || canonical_identity), 1, 16)
-- computed in the application layer (src/graph/uid.ts) so the same asset from
-- DNS, CT logs and port scans collapses to one row.

CREATE TABLE IF NOT EXISTS graph_nodes (
  uid            TEXT PRIMARY KEY,
  type           TEXT NOT NULL CHECK (type IN (
    'org','domain','subdomain','ip','host','port','service','os','webapp','api',
    'endpoint','cloud_account','cloud_resource','iam_role','container_image',
    'certificate','finding','evidence','sensor')),
  identity       TEXT NOT NULL,
  display        TEXT NOT NULL,
  attributes     JSONB NOT NULL DEFAULT '{}'::jsonb,
  first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
  valid_from     TIMESTAMPTZ NOT NULL DEFAULT now(),
  valid_to       TIMESTAMPTZ,
  observed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  provenance     TEXT[] NOT NULL DEFAULT '{}',
  path           LTREE NOT NULL  -- adjacency path, e.g. 'org.acme.domain.x.ip.y'
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_graph_nodes_type_identity ON graph_nodes (type, identity);
CREATE INDEX IF NOT EXISTS ix_graph_nodes_path ON graph_nodes USING GIST (path);
CREATE INDEX IF NOT EXISTS ix_graph_nodes_type ON graph_nodes (type);

CREATE TABLE IF NOT EXISTS graph_edges (
  uid            TEXT PRIMARY KEY,  -- 'edge:<type>:<src>:<dst>'
  edge_type      TEXT NOT NULL CHECK (edge_type IN (
    'resolves_to','hosts','exposes','runs','member_of','assumes','trusts',
    'reachable_from','derived_from','found_on')),
  src_uid        TEXT NOT NULL REFERENCES graph_nodes(uid),
  dst_uid        TEXT NOT NULL REFERENCES graph_nodes(uid),
  first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
  valid_from     TIMESTAMPTZ NOT NULL DEFAULT now(),
  valid_to       TIMESTAMPTZ,
  observed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  provenance     TEXT[] NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS ix_graph_edges_src ON graph_edges (src_uid) WHERE valid_to IS NULL;
CREATE INDEX IF NOT EXISTS ix_graph_edges_dst ON graph_edges (dst_uid) WHERE valid_to IS NULL;
CREATE INDEX IF NOT EXISTS ix_graph_edges_type ON graph_edges (edge_type);

-- NormalizedEvent log (OCSF-aligned). Dedupe key: (class_uid, asset_uid, observable_hash).
-- severity_raw is written once and NEVER updated; only severity_norm may ratchet up.
CREATE TABLE IF NOT EXISTS graph_events (
  id              BIGSERIAL PRIMARY KEY,
  class_uid       TEXT NOT NULL,          -- e.g. easm.host.resolved / dast.finding.observed
  activity_id     TEXT NOT NULL,          -- observed | opened | closed
  asset_uid       TEXT NOT NULL REFERENCES graph_nodes(uid),
  source_uid      TEXT,
  observables     JSONB NOT NULL,         -- [{kind, value}]
  observable_hash TEXT NOT NULL,
  severity_raw    TEXT NOT NULL,
  severity_norm   TEXT NOT NULL,
  confidence      TEXT NOT NULL,
  time            TIMESTAMPTZ NOT NULL DEFAULT now(),
  first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
  evidence_ref    TEXT,
  provenance      JSONB NOT NULL DEFAULT '[]'::jsonb,
  times_seen      INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_graph_events_dedupe
  ON graph_events (class_uid, asset_uid, observable_hash);
CREATE INDEX IF NOT EXISTS ix_graph_events_asset ON graph_events (asset_uid);
CREATE INDEX IF NOT EXISTS ix_graph_events_class ON graph_events (class_uid);

-- Blast-radius example (3.1/C4): everything reachable from an edge-exposed ip
-- within 4 hops:
--   WITH RECURSIVE reach AS (
--     SELECT uid, uid AS origin, 0 AS depth FROM graph_nodes WHERE uid = $1
--     UNION ALL
--     SELECT n.uid, r.origin, r.depth + 1
--     FROM reach r
--     JOIN graph_edges e ON e.valid_to IS NULL AND (e.src_uid = r.uid OR e.dst_uid = r.uid)
--     JOIN graph_nodes n ON n.uid IN (e.src_uid, e.dst_uid)
--     WHERE r.depth < 4
--   )
--   SELECT DISTINCT uid FROM reach;
