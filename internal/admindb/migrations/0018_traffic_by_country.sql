-- Access-log traffic by viewer country. Counts only, so no client address
-- is ever held. Minute rows serve the live view and are kept for two hours;
-- hour rows serve periods and are kept as long as the other stats. Country
-- is an ISO 3166 alpha-2 code, "unknown" or "*" (counts past the pending cap).
CREATE TABLE traffic_minute (
    minute    timestamptz NOT NULL,
    country   text NOT NULL CHECK (length(country) BETWEEN 1 AND 7),
    requests  bigint NOT NULL,
    blocked   bigint NOT NULL,
    estimated bigint NOT NULL,
    PRIMARY KEY (minute, country)
);
CREATE TABLE traffic_hour (
    hour      timestamptz NOT NULL,
    country   text NOT NULL CHECK (length(country) BETWEEN 1 AND 7),
    requests  bigint NOT NULL,
    blocked   bigint NOT NULL,
    estimated bigint NOT NULL,
    PRIMARY KEY (hour, country)
);
