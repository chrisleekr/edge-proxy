-- Autopilot: cases for the LLM runner, the runs that answered them, what
-- the model saw and said, the rules it proposed and how they ended. Runs,
-- events, results, proposals, transitions and prices are append-only, like
-- audit_events: the runtime role has only INSERT and SELECT, and triggers
-- stop the owner too.

INSERT INTO role_permissions VALUES
    ('viewer', 'autopilot.read'), ('editor', 'autopilot.read'), ('publisher', 'autopilot.read'), ('admin', 'autopilot.read'),
    ('publisher', 'autopilot.manage'), ('admin', 'autopilot.manage');

-- One row per runner instance, for the agent-connected status. Provider
-- names only: credentials never reach admin.
CREATE TABLE autopilot_runners (
    id          text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 100),
    version     text NOT NULL CHECK (length(version) <= 100),
    sdk_version text NOT NULL CHECK (length(sdk_version) <= 200),
    providers   text[] NOT NULL CHECK (providers <@ ARRAY['claude', 'openai']),
    last_seen   timestamptz NOT NULL
);

CREATE TABLE autopilot_cases (
    id          bigserial PRIMARY KEY,
    kind        text NOT NULL CHECK (kind IN ('anomaly', 'sweep', 'review', 'investigate')),
    -- One open case per key: a rule, an anomaly, or the sweep or review.
    dedupe_key  text NOT NULL,
    rule        text,
    route_id    bigint,
    anomaly_id  bigint,
    question    text NOT NULL DEFAULT '' CHECK (length(question) <= 2000),
    brief       jsonb NOT NULL DEFAULT '{}',
    state       text NOT NULL CHECK (state IN ('queued', 'running', 'done', 'failed', 'cancelled')),
    attempts    int NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 2),
    lease_until timestamptz,
    run_id      bigint,
    verdict     text CHECK (verdict IN ('attack', 'benign', 'unsure')),
    summary     text NOT NULL DEFAULT '',
    opened_by   text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- When the case was last queued: opened, or requeued for another attempt.
    queued_at   timestamptz NOT NULL DEFAULT now(),
    closed_at   timestamptz
);
CREATE UNIQUE INDEX autopilot_cases_open ON autopilot_cases (dedupe_key) WHERE state IN ('queued', 'running');
CREATE INDEX autopilot_cases_state ON autopilot_cases (state, created_at);

-- Prices per million tokens in micro-USD, versioned by effective_from, so
-- a past run is priced at the rate it ran under. None are seeded.
CREATE TABLE autopilot_model_prices (
    id                             bigserial PRIMARY KEY,
    provider                       text NOT NULL CHECK (provider IN ('claude', 'openai')),
    model                          text NOT NULL CHECK (model ~ '^[A-Za-z0-9._:/@-]{1,100}$'),
    input_usd_micros_per_mtok       bigint NOT NULL CHECK (input_usd_micros_per_mtok BETWEEN 0 AND 1000000000),
    output_usd_micros_per_mtok      bigint NOT NULL CHECK (output_usd_micros_per_mtok BETWEEN 0 AND 1000000000),
    cache_read_usd_micros_per_mtok  bigint NOT NULL CHECK (cache_read_usd_micros_per_mtok BETWEEN 0 AND 1000000000),
    cache_write_usd_micros_per_mtok bigint NOT NULL CHECK (cache_write_usd_micros_per_mtok BETWEEN 0 AND 1000000000),
    effective_from                 timestamptz NOT NULL,
    author                         text NOT NULL
);
CREATE INDEX autopilot_model_prices_model ON autopilot_model_prices (model, effective_from);

CREATE TABLE autopilot_runs (
    id             bigserial PRIMARY KEY,
    case_id        bigint NOT NULL REFERENCES autopilot_cases,
    attempt        int NOT NULL CHECK (attempt BETWEEN 1 AND 2),
    runner         text NOT NULL,
    runner_version text NOT NULL,
    sdk_version    text NOT NULL,
    provider       text NOT NULL CHECK (provider IN ('claude', 'openai')),
    model          text NOT NULL,
    prompt_sha256  bytea NOT NULL CHECK (length(prompt_sha256) = 32),
    tools_sha256   bytea NOT NULL CHECK (length(tools_sha256) = 32),
    started_at     timestamptz NOT NULL
);
CREATE INDEX autopilot_runs_started ON autopilot_runs (started_at);
ALTER TABLE autopilot_cases ADD FOREIGN KEY (run_id) REFERENCES autopilot_runs;

CREATE TABLE autopilot_run_results (
    run_id                     bigint PRIMARY KEY REFERENCES autopilot_runs,
    finished_at                timestamptz NOT NULL,
    status                     text NOT NULL CHECK (status IN ('ok', 'error', 'timeout', 'lease_lost')),
    error_category             text NOT NULL DEFAULT '' CHECK (length(error_category) <= 64),
    turns                      int NOT NULL CHECK (turns >= 0),
    tool_calls                 int NOT NULL CHECK (tool_calls >= 0),
    input_tokens               bigint NOT NULL CHECK (input_tokens BETWEEN 0 AND 1000000000),
    output_tokens              bigint NOT NULL CHECK (output_tokens BETWEEN 0 AND 1000000000),
    cache_read_tokens          bigint NOT NULL CHECK (cache_read_tokens BETWEEN 0 AND 1000000000),
    cache_write_tokens         bigint NOT NULL CHECK (cache_write_tokens BETWEEN 0 AND 1000000000),
    -- NULL when the model has no price, or the provider gave no estimate.
    price_id                   bigint REFERENCES autopilot_model_prices,
    configured_cost_usd_micros bigint,
    provider_cost_usd_micros   bigint,
    transcript_bytes           bigint NOT NULL CHECK (transcript_bytes >= 0),
    transcript_sha256          bytea CHECK (length(transcript_sha256) = 32),
    events_sha256              bytea CHECK (length(events_sha256) = 32),
    -- false when a runner event seq is missing.
    telemetry_complete         boolean NOT NULL
);

-- source admin is every MCP call, recorded by admin; runner is what the
-- model wrote, as the runner reports it. Each source numbers its own.
CREATE TABLE autopilot_run_events (
    id             bigserial PRIMARY KEY,
    run_id         bigint NOT NULL REFERENCES autopilot_runs,
    source         text NOT NULL CHECK (source IN ('admin', 'runner')),
    seq            int NOT NULL CHECK (seq > 0),
    kind           text NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    at             timestamptz NOT NULL,
    payload        jsonb NOT NULL,
    -- bytes and payload_sha256 are of the payload as sent, also when cut.
    bytes          int NOT NULL CHECK (bytes >= 0),
    payload_sha256 bytea NOT NULL CHECK (length(payload_sha256) = 32),
    cut            boolean NOT NULL,
    UNIQUE (run_id, source, seq)
);

CREATE TABLE autopilot_proposals (
    id          bigserial PRIMARY KEY,
    case_id     bigint NOT NULL REFERENCES autopilot_cases,
    run_id      bigint NOT NULL REFERENCES autopilot_runs,
    action      text NOT NULL CHECK (action IN ('add_sensor', 'enforce', 'retire')),
    rule_id     text,
    rule        jsonb NOT NULL DEFAULT '{}',
    ttl_seconds int,
    rationale   text NOT NULL CHECK (length(rationale) <= 4000),
    evidence    jsonb NOT NULL DEFAULT '{}',
    checks      jsonb NOT NULL DEFAULT '[]',
    accepted    boolean NOT NULL,
    -- The same proposal from the same case is one row: a retried call
    -- gets the first answer.
    rule_sha256 bytea NOT NULL CHECK (length(rule_sha256) = 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (case_id, rule_sha256)
);

-- Rules the autopilot published or will publish. state is where each one
-- is now; autopilot_transitions keeps how it got there.
CREATE TABLE autopilot_rules (
    id              text PRIMARY KEY CHECK (id LIKE 'ap-%'),
    proposal_id     bigint NOT NULL REFERENCES autopilot_proposals,
    case_id         bigint NOT NULL REFERENCES autopilot_cases,
    kind            text NOT NULL CHECK (kind IN ('sensor', 'enforce')),
    state           text NOT NULL CHECK (state IN ('proposed', 'observing', 'enforcing', 'rejected', 'expired', 'retired', 'rolled_back', 'adopted')),
    rule            jsonb NOT NULL,
    -- The expression and key, to suppress a rule shown wrong.
    shape_sha256    bytea NOT NULL CHECK (length(shape_sha256) = 32),
    ttl_seconds     int NOT NULL CHECK (ttl_seconds > 0),
    -- The sensor an enforcing rule cites; its lifetime counts from it.
    cites           text,
    live_since      timestamptz,
    enforcing_since timestamptz,
    shadow_ratio    double precision,
    expires_at      timestamptz,
    approved_by     text,
    ended_at        timestamptz,
    outcome         text CHECK (outcome IN ('expired', 'retired', 'retired_by_review', 'rolled_back', 'false_positive', 'adopted', 'rejected')),
    guard_alerted_at timestamptz
);
CREATE INDEX autopilot_rules_state ON autopilot_rules (state);

CREATE TABLE autopilot_transitions (
    id          bigserial PRIMARY KEY,
    rule_id     text NOT NULL REFERENCES autopilot_rules,
    case_id     bigint,
    proposal_id bigint,
    from_state  text NOT NULL,
    to_state    text NOT NULL,
    reason      text NOT NULL,
    -- The shadow and guard numbers that decided it.
    numbers     jsonb NOT NULL DEFAULT '{}',
    version     bigint,
    actor       text NOT NULL,
    at          timestamptz NOT NULL
);
CREATE INDEX autopilot_transitions_rule ON autopilot_transitions (rule_id, at);

CREATE FUNCTION autopilot_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END
$$;
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['autopilot_model_prices', 'autopilot_runs', 'autopilot_run_results', 'autopilot_run_events', 'autopilot_proposals', 'autopilot_transitions'] LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION autopilot_append_only()', t || '_no_change', t);
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION autopilot_append_only()', t || '_no_truncate', t);
    END LOOP;
END $$;
