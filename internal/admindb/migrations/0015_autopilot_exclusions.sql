-- Exclusions: a client a person found legitimate on a host, and optionally
-- a path prefix. Every autopilot rule proposed while one is active leaves
-- that traffic out of its expression. Only a person makes or ends one, and
-- a row is never deleted: revoking it keeps who did it and why.
CREATE TABLE autopilot_exclusions (
    id            bigserial PRIMARY KEY,
    subject       cidr NOT NULL,
    host          text NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    path_prefix   text NOT NULL DEFAULT '' CHECK (length(path_prefix) <= 200),
    reason        text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    -- The sensor it was promoted from, if any.
    rule_id       text REFERENCES autopilot_rules,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz,
    revoked_at    timestamptz,
    revoked_by    text,
    revoke_reason text CHECK (length(revoke_reason) <= 500),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE INDEX autopilot_exclusions_open ON autopilot_exclusions (id) WHERE revoked_at IS NULL;

-- The exclusions an autopilot rule's published expression carries, so the
-- rule can be ended when one of them is.
ALTER TABLE autopilot_rules ADD COLUMN exclusions bigint[] NOT NULL DEFAULT '{}';
