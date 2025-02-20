-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS downtimes (
    uuid TEXT PRIMARY KEY,
    created_by TEXT NOT NULL,
    class TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    start_time INTEGER NOT NULL,  -- Stored as Unix epoch (UTC, Milliseconds)
    end_time INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),  -- Stored as Unix epoch (UTC, Milliseconds)
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX idx_downtimes_start_time ON downtimes(start_time);
CREATE INDEX idx_downtimes_end_time ON downtimes(end_time);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS downtimes;
-- +goose StatementEnd
