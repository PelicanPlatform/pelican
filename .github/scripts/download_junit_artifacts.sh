#!/usr/bin/env bash

# Download JUnit artifacts from recent GitHub Actions workflow runs.
#
# Usage: download_junit_artifacts.sh WORKFLOW_NAME
#
# Arguments:
#   WORKFLOW_NAME  The name of the workflow to download artifacts from.
#
# Environment variables (set automatically by GitHub Actions):
#   GH_TOKEN            GitHub token for authentication.
#   GITHUB_REPOSITORY   The owner and repository name (e.g., "owner/repo").
#   GITHUB_RUN_ID       The unique ID of the current workflow run.
#   GITHUB_STEP_SUMMARY Path to the file for adding content to the job summary.

set -euo pipefail

workflow_name="$1"

# Get the last 14 completed workflow runs.
run_ids=$(gh run list \
  --repo "$GITHUB_REPOSITORY" \
  --workflow "$workflow_name" \
  --status completed \
  --limit 14 \
  --json databaseId \
  --jq '.[].databaseId')

# Add the current workflow run.
run_ids=$(printf '%s\n%s' "$run_ids" "$GITHUB_RUN_ID")

# Download artifacts for each run into their own directory.
for run_id in $run_ids; do
  echo "Downloading artifacts from run $run_id"
  mkdir -p "artifacts/run-$run_id"
  gh run download "$run_id" \
    --repo "$GITHUB_REPOSITORY" \
    --dir "artifacts/run-$run_id" || echo "No artifacts found for run $run_id"
done

printf 'Downloaded artifacts from %s runs\n\n' "$(echo "$run_ids" | wc -l)" >> "$GITHUB_STEP_SUMMARY"
