-- +goose Up
-- Add retry_count column to jobs table
ALTER TABLE jobs ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0;

-- Add retry_count column to job_history table
ALTER TABLE job_history ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0;

-- +goose Down
-- Remove retry_count column from job_history table
ALTER TABLE job_history DROP COLUMN retry_count;

-- Remove retry_count column from jobs table
ALTER TABLE jobs DROP COLUMN retry_count;
