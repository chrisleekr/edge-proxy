-- The UPSTREAM_URL each edge reports, shown read-only on the Fleet page.
-- It is deployment config: admin only displays it and never sends it back.
ALTER TABLE fleet ADD COLUMN upstream text NOT NULL DEFAULT '';
