-- Why a canary was aborted by hand, shown on the version so readers
-- don't need the audit log.
ALTER TABLE config_versions ADD COLUMN abort_reason text;
