-- Requests counted from sampled access lines, each standing for 1/rate
-- requests, so readers can tell an estimate from an exact count.
ALTER TABLE observed_route_hour ADD COLUMN estimated bigint NOT NULL DEFAULT 0;
