-- +goose Up
-- +goose StatementBegin
ALTER TABLE namespace
ADD COLUMN prohibited_caches TEXT DEFAULT '[]';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE namespace
DROP COLUMN prohibited_caches;
-- +goose StatementEnd
