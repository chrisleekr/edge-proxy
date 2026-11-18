-- Requests per client signal, in the edge's signal order. Empty for minutes
-- stored before the edge reported it; sums pad shorter arrays with zeros.
ALTER TABLE edge_stats_minute ADD COLUMN client_signals bigint[] NOT NULL DEFAULT '{}';
