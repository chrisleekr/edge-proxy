-- Latest good verified crawler ranges per VERIFIED_BOT_SOURCES URL, as
-- canonical prefixes, so a reformatted list is not a change. They reach
-- edges in the snapshot, outside policy versions.
CREATE TABLE verified_bot_sets (
    source_url text PRIMARY KEY CHECK (length(source_url) <= 2048),
    fetched_at timestamptz NOT NULL,
    prefixes   jsonb NOT NULL CHECK (jsonb_typeof(prefixes) = 'array' AND jsonb_array_length(prefixes) BETWEEN 1 AND 2000)
);
