-- Status codes by origin, {"edge": {"502": n}, "upstream": {...}}, and the
-- edge's upstream failures by cause, {"refused": n}, summed per minute like
-- rate_limit.
ALTER TABLE edge_stats_minute ADD COLUMN status_codes jsonb NOT NULL DEFAULT '{}';
ALTER TABLE edge_stats_minute ADD COLUMN upstream_errors jsonb NOT NULL DEFAULT '{}';

-- Answers per status code, {"502": n}, weighted like status, and upstream
-- failures by cause from the access lines' edge.upstream_error_kind.
ALTER TABLE observed_route_hour ADD COLUMN status_codes jsonb NOT NULL DEFAULT '{}';
ALTER TABLE observed_route_hour ADD COLUMN upstream_errors jsonb NOT NULL DEFAULT '{}';
