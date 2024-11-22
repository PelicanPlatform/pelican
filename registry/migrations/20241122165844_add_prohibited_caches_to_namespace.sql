-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
ALTER TABLE namespace
ADD COLUMN prohibited_caches TEXT DEFAULT '[]';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
ALTER TABLE namespace
DROP COLUMN prohibited_caches;
-- +goose StatementEnd
