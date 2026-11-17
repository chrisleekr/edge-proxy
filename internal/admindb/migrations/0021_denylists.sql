-- IP list sources managed in the admin UI. Admin downloads each enabled
-- source and keeps its last good copy, and edges read the merged set from
-- GET /v1/denylist, outside policy versions.
CREATE TABLE denylist_sources (
    id       bigserial PRIMARY KEY,
    url      text NOT NULL UNIQUE CHECK (length(url) <= 2048),
    enabled  boolean NOT NULL DEFAULT true,
    added_by text NOT NULL,
    added_at timestamptz NOT NULL
);

-- The normalized list, one prefix per line in text order. Its row version
-- is part of the edge ETag, so only a changed list rewrites it.
CREATE TABLE denylist_sets (
    source_id  bigint PRIMARY KEY REFERENCES denylist_sources ON DELETE CASCADE,
    fetched_at timestamptz NOT NULL,
    entries    int NOT NULL CHECK (entries >= 1),
    prefixes   text NOT NULL
);

-- Fetch telemetry, apart from denylist_sets so a status write on every
-- attempt never changes the edge ETag. A null last_attempt_at makes the
-- source due, which is how Refresh works.
CREATE TABLE denylist_status (
    source_id       bigint PRIMARY KEY REFERENCES denylist_sources ON DELETE CASCADE,
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    failures        int NOT NULL CHECK (failures >= 0),
    last_error      text CHECK (length(last_error) <= 300),
    skipped         int NOT NULL DEFAULT 0 CHECK (skipped >= 0)
);

-- Bans the edges report, one row per replica and ban key. Telemetry, not
-- audit data: lifts are audited. lifted_at is set when a person lifts the
-- ban, until the edges have applied it.
CREATE TABLE bans (
    replica    text NOT NULL CHECK (length(replica) <= 128),
    ip         text NOT NULL,
    rule       text NOT NULL,
    host       text NOT NULL,
    path       text NOT NULL,
    started_at timestamptz NOT NULL,
    ends_at    timestamptz NOT NULL,
    lifted_at  timestamptz,
    PRIMARY KEY (replica, ip)
);
CREATE INDEX bans_ends_at ON bans (ends_at);

-- Lifts edges apply when they poll, kept for the longest ban.
CREATE TABLE ban_lifts (
    id        bigserial PRIMARY KEY,
    ip        text NOT NULL,
    lifted_at timestamptz NOT NULL,
    actor     text NOT NULL
);

-- A list change alters enforcement on every edge without a publish, so it
-- sits with publish rights.
INSERT INTO role_permissions VALUES ('publisher', 'denylists.manage'), ('admin', 'denylists.manage');
