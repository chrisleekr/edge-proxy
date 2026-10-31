-- Autopilot memory: notes a case run records for later cases. A note's
-- current state is in autopilot_notes; how it got there is in
-- autopilot_note_revisions, and every time it was served, re-checked or
-- cited is in autopilot_note_uses. Both are append-only, like the rest of
-- the autopilot's record.

-- An ablation case re-runs an earlier case with notes withheld.
ALTER TABLE autopilot_cases DROP CONSTRAINT autopilot_cases_kind_check;
ALTER TABLE autopilot_cases ADD CONSTRAINT autopilot_cases_kind_check CHECK (kind IN ('anomaly', 'sweep', 'review', 'investigate', 'ablation'));
ALTER TABLE autopilot_cases ADD COLUMN ablation_of bigint REFERENCES autopilot_cases;
ALTER TABLE autopilot_cases ADD COLUMN withheld_notes bigint[] NOT NULL DEFAULT '{}';

CREATE TABLE autopilot_notes (
    id          bigserial PRIMARY KEY,
    kind        text NOT NULL CHECK (kind IN ('context', 'expected_pattern', 'attack_signature', 'collateral_risk', 'key_preference')),
    basis       text NOT NULL CHECK (basis IN ('observed', 'hypothesis')),
    scope       jsonb NOT NULL,
    scope_key   text NOT NULL CHECK (length(scope_key) BETWEEN 1 AND 700),
    claim       jsonb,
    effect      jsonb,
    statement   text NOT NULL CHECK (length(statement) BETWEEN 1 AND 500),
    rationale   text NOT NULL DEFAULT '' CHECK (length(rationale) <= 1000),
    -- What admin computed from its own data when the note was written.
    stats       jsonb,
    links       jsonb NOT NULL DEFAULT '{}',
    -- The cited reads as references to run events, which are never pruned.
    evidence    jsonb NOT NULL DEFAULT '[]',
    anchor      text CHECK (anchor IN ('history', 'crawler', 'protected', 'jwt_claim')),
    trust       text NOT NULL CHECK (trust IN ('unconfirmed', 'confirmed', 'dormant', 'retracted', 'retired')),
    trust_since timestamptz NOT NULL,
    -- Unmatched uses in a row; the third makes the note dormant.
    fail_streak int NOT NULL DEFAULT 0,
    served_at   timestamptz,
    case_id     bigint NOT NULL REFERENCES autopilot_cases,
    run_id      bigint NOT NULL REFERENCES autopilot_runs,
    created_at  timestamptz NOT NULL,
    CHECK (basis = 'hypothesis' AND kind = 'context' AND claim IS NULL OR basis = 'observed' AND claim IS NOT NULL)
);
CREATE INDEX autopilot_notes_scope ON autopilot_notes (scope_key) WHERE trust IN ('unconfirmed', 'confirmed', 'dormant');
CREATE INDEX autopilot_notes_trust ON autopilot_notes (trust);
CREATE INDEX autopilot_notes_run ON autopilot_notes (run_id);

CREATE TABLE autopilot_note_revisions (
    id      bigserial PRIMARY KEY,
    note_id bigint NOT NULL REFERENCES autopilot_notes,
    change  text NOT NULL CHECK (change IN ('written', 'confirmed', 'contested', 'dormant', 'retired', 'retracted')),
    trust   text NOT NULL,
    reason  text NOT NULL DEFAULT '' CHECK (length(reason) <= 1000),
    -- The whole note as written.
    fields  jsonb,
    actor   text NOT NULL,
    run_id  bigint REFERENCES autopilot_runs,
    case_id bigint REFERENCES autopilot_cases,
    at      timestamptz NOT NULL,
    CHECK ((change = 'written') = (fields IS NOT NULL))
);
CREATE INDEX autopilot_note_revisions_note ON autopilot_note_revisions (note_id, id);
CREATE INDEX autopilot_note_revisions_change ON autopilot_note_revisions (change, at);

-- source search is a run's search_notes, propose a proposal citing the
-- note, review admin's daily re-check, which no run makes.
CREATE TABLE autopilot_note_uses (
    id          bigserial PRIMARY KEY,
    note_id     bigint NOT NULL REFERENCES autopilot_notes,
    revision_id bigint NOT NULL REFERENCES autopilot_note_revisions,
    source      text NOT NULL CHECK (source IN ('search', 'propose', 'review')),
    run_id      bigint REFERENCES autopilot_runs,
    case_id     bigint REFERENCES autopilot_cases,
    proposal_id bigint REFERENCES autopilot_proposals,
    matched     boolean NOT NULL,
    cited       boolean NOT NULL,
    -- The claim's value on the use's window, or NULL for a hypothesis.
    value       double precision,
    at          timestamptz NOT NULL,
    CHECK (source = 'review' OR run_id IS NOT NULL),
    CHECK (cited = (source = 'propose'))
);
CREATE INDEX autopilot_note_uses_note ON autopilot_note_uses (note_id, at);
CREATE INDEX autopilot_note_uses_proposal ON autopilot_note_uses (proposal_id) WHERE cited;
CREATE INDEX autopilot_note_uses_run ON autopilot_note_uses (run_id);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['autopilot_note_revisions', 'autopilot_note_uses'] LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION autopilot_append_only()', t || '_no_change', t);
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION autopilot_append_only()', t || '_no_truncate', t);
    END LOOP;
END $$;
