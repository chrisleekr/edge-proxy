-- Refresh status of each VERIFIED_BOT_SOURCES list. Kept apart from
-- verified_bot_sets because that table's row versions make up the edge
-- snapshot ETag, and a status write on every refresh must not change it.
-- Status is telemetry like fleet; the anomaly it raises is what is audited.
CREATE TABLE verified_bot_status (
    source_url      text PRIMARY KEY CHECK (length(source_url) <= 2048),
    last_attempt_at timestamptz NOT NULL,
    last_success_at timestamptz,
    failures        int NOT NULL CHECK (failures >= 0),
    last_error      text CHECK (length(last_error) <= 300)
);
