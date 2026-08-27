#!/usr/bin/env python3

"""Convert one or more "go tool cover -func" reports into a single JSON file.

Usage: coverage_to_json.py INPUT_DIR OUTPUT_FILE

Arguments:
  INPUT_DIR    Directory containing "coverage-func-<name>.txt" files, each the
               stdout of "go tool cover -func=<profile>".
  OUTPUT_FILE  Path to write the combined coverage JSON to.

The output shape is:

  {
    "commit": "<git sha>",
    "run_id": "<actions run id>",
    "profiles": {
      "<name>": {
        "total": 71.2,
        "functions": [
          {"file": "...", "line": 12, "function": "Foo", "coverage": 85.7},
          ...
        ]
      },
      ...
    }
  }

Per-profile "total" is Go's statement-weighted total for that profile. We do
not synthesize a single cross-profile total because the profiles are collected
from separate test runs (client vs. server) and cannot be averaged naively.
"""

import glob
import json
import os
import sys


def parse_func_report(path):
    """Parse a single "go tool cover -func" report file.

    Returns a dict: {"total": float|None, "functions": [ ... ]}.
    """
    functions = []
    total = None

    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue

            # Columns are whitespace-separated. None of the columns (file path,
            # function name, percentage) contain spaces, so a plain split is
            # safe. The last column is always the percentage, e.g. "85.7%".
            parts = line.split()
            if len(parts) < 3:
                continue

            percent = float(parts[-1].rstrip("%"))

            if parts[0] == "total:":
                total = percent
                continue

            # parts[0] looks like "path/to/file.go:12:"; peel off the trailing
            # colon and split the line number from the file path.
            location = parts[0].rstrip(":")
            file_path, _, line_no = location.rpartition(":")
            functions.append(
                {
                    "file": file_path,
                    "line": int(line_no),
                    "function": parts[1],
                    "coverage": percent,
                }
            )

    return {"total": total, "functions": functions}


def profile_name(path):
    """Derive a profile name from a "coverage-func-<name>.txt" filename."""
    base = os.path.basename(path)
    base = base[len("coverage-func-"):] if base.startswith("coverage-func-") else base
    if base.endswith(".txt"):
        base = base[: -len(".txt")]
    return base


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: coverage_to_json.py INPUT_DIR OUTPUT_FILE\n")
        return 2

    input_dir, output_file = argv[1], argv[2]

    # Search recursively: "gh run download" places each artifact in its own
    # subdirectory, while other layouts drop the files in flat.
    report_paths = sorted(
        glob.glob(os.path.join(input_dir, "**", "coverage-func-*.txt"), recursive=True)
    )
    if not report_paths:
        sys.stderr.write(f"no coverage-func-*.txt files found in {input_dir}\n")
        return 1

    profiles = {profile_name(p): parse_func_report(p) for p in report_paths}

    document = {
        "commit": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "profiles": profiles,
    }

    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")

    for name, data in profiles.items():
        print(f"{name}: total={data['total']}% functions={len(data['functions'])}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
