-- Acknowledged dashboard items. An ack hides one condition for the whole
-- team until it clears. Rows are not audit data (the audit log records each
-- ack and clear), so the runtime role may delete them.
CREATE TABLE attention_acks (
    key      text PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 200),
    summary  text NOT NULL CHECK (length(summary) BETWEEN 1 AND 500),
    actor    text NOT NULL,
    acked_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO role_permissions VALUES
    ('editor', 'attention.ack'), ('publisher', 'attention.ack'), ('admin', 'attention.ack');
