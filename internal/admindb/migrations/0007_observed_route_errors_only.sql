-- A route seen only with error answers, such as a login whose every request
-- is rate limited. Kept apart from other routes, with its own cap, so a
-- scanner's 404s can't push them out; cleared on its first other answer.
ALTER TABLE observed_routes ADD COLUMN errors_only boolean NOT NULL DEFAULT false;
