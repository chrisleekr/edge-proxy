-- Log-only counts are named logged everywhere. Audit rows and note revisions
-- are history and keep the names they were written with.
CREATE FUNCTION rename_count(a jsonb, old text) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
	SELECT coalesce(jsonb_agg(CASE WHEN e ? old THEN (e - old) || jsonb_build_object('logged', e -> old) ELSE e END ORDER BY n), '[]')
	FROM jsonb_array_elements(a) WITH ORDINALITY t(e, n)
$$;
UPDATE edge_stats_minute SET
	rate_limit = rename_count(rate_limit, 'would_limit'),
	top_limited = rename_count(top_limited, 'would_limit'),
	rules = rename_count(rules, 'would_block')
WHERE rate_limit::text LIKE '%"would_limit"%' OR top_limited::text LIKE '%"would_limit"%' OR rules::text LIKE '%"would_block"%';
DROP FUNCTION rename_count(jsonb, text);

-- Those requests were let through, so their count moves to allow. Which rule
-- logged them was never stored, so logged_rules starts empty.
ALTER TABLE observed_route_hour RENAME COLUMN decisions TO actions;
ALTER TABLE observed_route_hour ADD COLUMN logged_rules jsonb NOT NULL DEFAULT '{}';
UPDATE observed_route_hour SET actions = (actions - 'would_block' - 'would_limit')
	|| jsonb_build_object('allow', coalesce((actions->>'allow')::bigint, 0) + coalesce((actions->>'would_block')::bigint, 0) + coalesce((actions->>'would_limit')::bigint, 0))
WHERE actions ?| array['would_block', 'would_limit'];

UPDATE anomalies SET signal = 'rule_logged' WHERE signal = 'rule_would_block';
UPDATE autopilot_cases SET brief = jsonb_set(brief, '{signal}', '"rule_logged"') WHERE brief->>'signal' = 'rule_would_block';
UPDATE autopilot_notes SET claim = jsonb_set(claim, '{metric}', '"rule_logged"') WHERE claim->>'metric' = 'rule_would_limit';
