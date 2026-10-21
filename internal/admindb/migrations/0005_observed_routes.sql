-- Routes observed in edge access logs, grouped by host, method and path
-- template. Stats only: nothing here feeds policy.
CREATE TABLE observed_routes (
    id         bigserial PRIMARY KEY,
    host       text NOT NULL,
    method     text NOT NULL,
    template   text NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    UNIQUE (host, method, template)
);

-- Hourly totals per route. Every replica adds its deltas to the same row, so
-- readers need no merging.
CREATE TABLE observed_route_hour (
    route_id         bigint NOT NULL REFERENCES observed_routes ON DELETE CASCADE,
    hour             timestamptz NOT NULL,
    requests         bigint NOT NULL,
    -- versioned counts lines served under a policy version, which is what
    -- the edges' own stats count; their ratio is the coverage shown.
    versioned        bigint NOT NULL,
    status           bigint[] NOT NULL, -- by class: index 0 is no response, then 1xx to 5xx
    latency_ms       bigint[] NOT NULL, -- by the edge's latency bucket bounds
    decisions        jsonb NOT NULL,
    config_rules     jsonb NOT NULL,
    rate_limit_rules jsonb NOT NULL,
    query_shapes     jsonb NOT NULL,
    PRIMARY KEY (route_id, hour)
);
CREATE INDEX observed_route_hour_hour ON observed_route_hour (hour);

-- Operator-defined groupings: "*" stands for one path segment.
CREATE TABLE route_patterns (
    id         bigserial PRIMARY KEY,
    host       text NOT NULL, -- '' means every host
    pattern    text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (host, pattern)
);

-- add_counts adds two arrays of counts by index.
CREATE FUNCTION add_counts(a bigint[], b bigint[]) RETURNS bigint[] LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(array_agg(coalesce(x, 0) + coalesce(y, 0) ORDER BY i), '{}')
    FROM unnest(a, b) WITH ORDINALITY AS u(x, y, i)
$$;

-- add_counts adds two {key: count} objects. Past cap keys, the smallest
-- counts are summed under "*", which no rule ID, query key or decision can
-- be, so a row never grows without bound.
CREATE FUNCTION add_counts(a jsonb, b jsonb, cap int) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(jsonb_object_agg(k, n), '{}') FROM (
        SELECT CASE WHEN rn <= cap THEN k ELSE '*' END AS k, sum(n) AS n FROM (
            SELECT k, n, row_number() OVER (ORDER BY n DESC, k) AS rn FROM (
                SELECT k, sum(v::bigint) AS n
                FROM (SELECT * FROM jsonb_each_text(a) UNION ALL SELECT * FROM jsonb_each_text(b)) e(k, v)
                GROUP BY k) summed) ranked
        GROUP BY 1) capped
$$;

-- sum_counts sums rows of counts when reading a time range. The jsonb form
-- collects the rows and sums them once: merging each row into a running
-- total rebuilds the total every time, quadratic in a long range's keys.
CREATE AGGREGATE sum_counts(bigint[]) (SFUNC = add_counts, STYPE = bigint[], INITCOND = '{}');
CREATE FUNCTION sum_counts_final(rows jsonb[]) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(jsonb_object_agg(k, n), '{}') FROM (
        SELECT k, sum(v::bigint) AS n FROM unnest(rows) r, jsonb_each_text(r) e(k, v) GROUP BY k) summed
$$;
CREATE AGGREGATE sum_counts(jsonb) (SFUNC = array_append, STYPE = jsonb[], FINALFUNC = sum_counts_final, INITCOND = '{}');

INSERT INTO role_permissions (role, permission) VALUES
    ('publisher', 'routes.manage'),
    ('admin', 'routes.manage');
