-- A verdict is split into the one-sentence answer (summary), the decisions
-- only a person can make (needs_you, a list of {rule, ask}) and the reasoning
-- (details). Older cases keep their long summary and have neither.
-- A sensor that reached its expiry without matching a request ends as unused,
-- which sweeps read so they do not propose it again.
ALTER TABLE autopilot_cases
    ADD COLUMN needs_you jsonb NOT NULL DEFAULT '[]',
    ADD COLUMN details   text  NOT NULL DEFAULT '';

ALTER TABLE autopilot_rules DROP CONSTRAINT autopilot_rules_outcome_check;
ALTER TABLE autopilot_rules ADD CONSTRAINT autopilot_rules_outcome_check
    CHECK (outcome IN ('expired', 'retired', 'retired_by_review', 'rolled_back', 'false_positive', 'adopted', 'rejected', 'unused'));
