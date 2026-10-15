-- A publisher can change the guard for one publish, with a reason.
-- Both are set or neither.
ALTER TABLE config_versions
    ADD COLUMN guard_override jsonb,
    ADD COLUMN guard_override_reason text,
    ADD CHECK ((guard_override IS NULL) = (guard_override_reason IS NULL));

-- The highest config schema each edge reads, so admin never publishes one
-- the oldest edge would refuse. Edges that predate the
-- field read schema 1.
ALTER TABLE fleet ADD COLUMN max_schema integer NOT NULL DEFAULT 1;
