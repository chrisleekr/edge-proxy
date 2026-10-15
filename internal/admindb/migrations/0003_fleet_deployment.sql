-- Each edge's deployment fingerprint, so admin never publishes a config
-- validated against different deployment settings than the edges run with.
-- Edges that predate the field report ''.
ALTER TABLE fleet ADD COLUMN deployment text NOT NULL DEFAULT '';
