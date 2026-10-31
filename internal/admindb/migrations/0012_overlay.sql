-- Rate-limit rules whose ids start "ap-" are autopilot's overlay. A rule a
-- person named that way in the live policy or the draft would be taken for
-- one, so the migration fails and names it. Rename the rule with the
-- previous release, then migrate again. Older versions are not checked:
-- they are not served.
DO $$
DECLARE
    bad text;
BEGIN
    SELECT rule_id #>> '{}' INTO bad
    FROM (SELECT config FROM config_versions WHERE status IN ('active', 'canary')
          UNION ALL SELECT config FROM config_draft) AS c,
         unnest(ARRAY['$.config_rules[*].id', '$.rate_limit_rules[*].id', '$.request_header_rules[*].id']::jsonpath[]) AS p,
         jsonb_path_query(c.config, p) AS rule_id
    WHERE rule_id #>> '{}' LIKE 'ap-%'
    LIMIT 1;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'rule id "%" starts with "ap-", which is now reserved for autopilot rules; rename it in the active version, canary and draft with the previous admin release, then upgrade again', bad;
    END IF;
END $$;

ALTER TABLE config_versions DROP CONSTRAINT config_versions_source_check;
ALTER TABLE config_versions ADD CONSTRAINT config_versions_source_check
    CHECK (source IN ('manual', 'revert', 'guard_rollback', 'import', 'autopilot'));

-- Overlay rules adopted into the draft since its last publish. That publish
-- drops them from the overlay.
ALTER TABLE config_draft ADD COLUMN adopted text[] NOT NULL DEFAULT '{}';
