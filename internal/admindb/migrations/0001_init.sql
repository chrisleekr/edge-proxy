-- Identity. Usernames are lowercase so lookups are exact.
CREATE TABLE users (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username   text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9._@-]{1,64}$'),
    email      text NOT NULL DEFAULT '',
    disabled   boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_identities (
    provider text NOT NULL,
    subject  text NOT NULL,
    user_id  uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    PRIMARY KEY (provider, subject)
);

CREATE TABLE local_credentials (
    user_id    uuid PRIMARY KEY REFERENCES users ON DELETE CASCADE,
    hash       text NOT NULL CHECK (hash LIKE '$argon2id$%'),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE roles (name text PRIMARY KEY);

CREATE TABLE role_permissions (
    role       text NOT NULL REFERENCES roles,
    permission text NOT NULL,
    PRIMARY KEY (role, permission)
);

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    role    text NOT NULL REFERENCES roles,
    PRIMARY KEY (user_id, role)
);

CREATE TABLE group_role_mappings (
    provider   text NOT NULL,
    group_name text NOT NULL,
    role       text NOT NULL REFERENCES roles,
    PRIMARY KEY (provider, group_name, role)
);

-- Handlers check permissions, never these role names.
INSERT INTO roles VALUES ('viewer'), ('editor'), ('publisher'), ('admin');
INSERT INTO role_permissions
SELECT r, p FROM (VALUES
    ('viewer', ARRAY['config.read', 'stats.read', 'audit.read']),
    ('editor', ARRAY['config.read', 'stats.read', 'audit.read', 'config.write', 'config.test']),
    ('publisher', ARRAY['config.read', 'stats.read', 'audit.read', 'config.write', 'config.test',
                        'config.publish', 'config.rollback', 'canary.manage']),
    ('admin', ARRAY['config.read', 'stats.read', 'audit.read', 'config.write', 'config.test',
                    'config.publish', 'config.rollback', 'canary.manage',
                    'users.manage', 'settings.manage', 'tokens.manage'])
) AS t(r, ps), unnest(ps) AS p;

-- Only the SHA-256 of a session ID or token is stored.
CREATE TABLE sessions (
    id_hash      bytea PRIMARY KEY CHECK (length(id_hash) = 32),
    user_id      uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz
);
CREATE INDEX sessions_user ON sessions (user_id);

-- Edge service tokens have no user.
CREATE TABLE api_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    name       text NOT NULL CHECK (name <> ''),
    kind       text NOT NULL CHECK (kind IN ('user', 'edge')),
    user_id    uuid REFERENCES users ON DELETE CASCADE,
    scopes     text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    revoked_at timestamptz,
    CHECK ((kind = 'edge') = (user_id IS NULL))
);

-- Config. Versions are kept forever and never deleted.
CREATE TABLE config_versions (
    version         bigint PRIMARY KEY CHECK (version > 0),
    author          text NOT NULL,
    published_at    timestamptz NOT NULL DEFAULT now(),
    message         text NOT NULL CHECK (message <> ''),
    source          text NOT NULL CHECK (source IN ('manual', 'revert', 'guard_rollback', 'import')),
    based_on        bigint REFERENCES config_versions,
    status          text NOT NULL CHECK (status IN ('active', 'canary', 'superseded', 'rolled_back')),
    config          jsonb NOT NULL,
    tests           jsonb NOT NULL DEFAULT '[]',
    test_results    jsonb,
    guard_outcome   jsonb,
    change_summary  text NOT NULL DEFAULT '',
    override_reason text,
    CHECK ((source IN ('revert', 'guard_rollback')) = (based_on IS NOT NULL))
);
CREATE UNIQUE INDEX config_versions_one_active ON config_versions ((true)) WHERE status = 'active';
CREATE UNIQUE INDEX config_versions_one_canary ON config_versions ((true)) WHERE status = 'canary';

-- The one shared draft.
CREATE TABLE config_draft (
    id           boolean PRIMARY KEY DEFAULT true CHECK (id),
    config       jsonb NOT NULL,
    tests        jsonb NOT NULL DEFAULT '[]',
    base_version bigint REFERENCES config_versions,
    revision     bigint NOT NULL DEFAULT 1,
    updated_by   text NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE canary (
    id              boolean PRIMARY KEY DEFAULT true CHECK (id),
    version         bigint NOT NULL REFERENCES config_versions,
    percent         numeric(4, 2) NOT NULL CHECK (percent >= 0.01 AND percent <= 99.99),
    started_at      timestamptz NOT NULL,
    step_started_at timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL
);

-- Latest good JWKS per issuer and URL. Keys belong to the URL.
CREATE TABLE jwks_keys (
    issuer_id  text NOT NULL,
    jwks_url   text NOT NULL,
    fetched_at timestamptz NOT NULL,
    jwks       bytea NOT NULL CHECK (length(jwks) <= 65536),
    PRIMARY KEY (issuer_id, jwks_url)
);

CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Edges reporting in.
CREATE TABLE fleet (
    instance              text PRIMARY KEY,
    last_seen             timestamptz NOT NULL,
    config_source         text NOT NULL,
    bootstrap_age_seconds bigint NOT NULL,
    versions              bigint[] NOT NULL
);

-- Per-minute totals by config version. Each admin replica writes its own
-- row for the reports it received; readers sum across replicas.
CREATE TABLE edge_stats_minute (
    minute        timestamptz NOT NULL,
    version       bigint NOT NULL,
    replica       text NOT NULL,
    requests      bigint NOT NULL,
    edge_5xx      bigint NOT NULL,
    upstream_5xx  bigint NOT NULL,
    auth_failures bigint NOT NULL,
    latency_ms    bigint[] NOT NULL,
    rate_limit    jsonb NOT NULL DEFAULT '[]',
    top_limited   jsonb NOT NULL DEFAULT '[]',
    PRIMARY KEY (minute, version, replica)
);
CREATE INDEX edge_stats_minute_version ON edge_stats_minute (version, minute);

-- Audit. Append-only: the app role has only INSERT and
-- SELECT, and these triggers stop the owner too.
CREATE TABLE audit_events (
    seq         bigint PRIMARY KEY CHECK (seq > 0),
    occurred_at timestamptz NOT NULL,
    actor       text NOT NULL,
    action      text NOT NULL,
    target      text NOT NULL DEFAULT '',
    -- json, not jsonb: json keeps the exact text, so the HMAC covers the
    -- stored bytes; jsonb would reorder keys and normalize numbers.
    details     json NOT NULL DEFAULT '{}',
    key_id      text NOT NULL,
    hmac        bytea NOT NULL CHECK (length(hmac) = 32)
);
CREATE INDEX audit_events_occurred ON audit_events (occurred_at);

CREATE FUNCTION audit_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END
$$;
CREATE TRIGGER audit_events_no_change BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();
