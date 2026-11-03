-- How the requests each config and request-header rule matched ended,
-- summed per minute like rate_limit.
ALTER TABLE edge_stats_minute ADD COLUMN rules jsonb NOT NULL DEFAULT '[]';

-- Anomalies the notification checks found. A signal and subject (a rule ID,
-- or '' for the whole fleet) has at most one open row, pending until it trips
-- fire_after checks in a row, then firing until it passes resolve_after.
-- Resolved rows stay for 30 days.
CREATE TABLE anomalies (
    id          bigserial PRIMARY KEY,
    signal      text NOT NULL,
    rule        text NOT NULL,
    phase       text NOT NULL,
    severity    text NOT NULL,
    state       text NOT NULL CHECK (state IN ('pending', 'firing', 'resolved')),
    tripped     int NOT NULL, -- checks in a row that tripped
    passed      int NOT NULL, -- checks in a row that passed, while firing
    started_at  timestamptz NOT NULL,
    fired_at    timestamptz,
    resolved_at timestamptz,
    -- notified_at is the last time Alertmanager accepted this anomaly.
    notified_at timestamptz,
    summary     text NOT NULL,
    details     jsonb NOT NULL
);
CREATE UNIQUE INDEX anomalies_open ON anomalies (signal, rule) WHERE state <> 'resolved';
CREATE INDEX anomalies_resolved_at ON anomalies (resolved_at);
