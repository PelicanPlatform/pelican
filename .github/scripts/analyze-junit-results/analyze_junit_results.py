#!/usr/bin/env python3
"""
Analyze JUnit XML artifacts from GitHub Actions workflow runs.

Reads JUnit XML files from the "artifacts/" directory
and writes a summary of test failures to "test-failure-analysis.md".
"""

import sys
import xml.etree.ElementTree as ET  # nosec B405  # XML is from our own CI runner, not user input
from collections import defaultdict
from pathlib import Path

# Track failures by matrix variant
failures_by_matrix: defaultdict[str, defaultdict[str, int]] = defaultdict(lambda: defaultdict(int))

# Find all JUnit XML files
artifacts_dir = Path("artifacts")
if not artifacts_dir.exists():
    print("No artifacts directory found")
    sys.exit(1)

for run_dir in sorted(artifacts_dir.iterdir()):
    if not run_dir.is_dir():
        continue

    # Process each matrix variant
    for artifact_dir in run_dir.iterdir():
        if not artifact_dir.is_dir() or not artifact_dir.name.startswith("junit-"):
            continue

        # Extract the matrix variant name by stripping the "junit-" prefix
        # and the OS suffix (e.g., "junit-pelican-Linux" -> "pelican")
        matrix_name = artifact_dir.name.removeprefix("junit-")
        for os_suffix in ("-Linux", "-macOS", "-Windows"):
            matrix_name = matrix_name.removesuffix(os_suffix)

        # Find JUnit XML files
        for xml_file in artifact_dir.glob("*.xml"):
            try:
                tree = ET.parse(xml_file)  # nosec B314  # XML is from our own CI runner, not user input
                root = tree.getroot()

                # Parse test cases
                for testcase in root.iter("testcase"):
                    classname = testcase.get("classname") or ""
                    test_name = f"{classname.split('/')[-1]}.{testcase.get('name')}"

                    # Check if the test failed
                    if (
                        testcase.find("failure") is not None
                        or testcase.find("error") is not None
                    ):
                        failures_by_matrix[matrix_name][test_name] += 1
            except (ET.ParseError, OSError) as e:
                print(f"Error parsing {xml_file}: {e}")

# Write results to file
with Path("test-failure-analysis.md").open(mode="w", encoding="utf-8") as fp:
    if not failures_by_matrix:
        fp.write("No failures found\n\n")
    else:
        for matrix_name in sorted(failures_by_matrix.keys()):
            fp.write(f"### {matrix_name}\n\n")

            failures = failures_by_matrix[matrix_name]
            if not failures:
                fp.write("No failures found\n\n")
                continue

            # Sort by failure count (descending), then by test name
            sorted_failures = sorted(failures.items(), key=lambda x: (-x[1], x[0]))

            fp.write(f"{len(failures)} tests with failures:\n\n")

            for test_name, count in sorted_failures:
                fp.write(f"- {count} failures: {test_name}\n\n")

print("Analysis complete. Results written to test-failure-analysis.md.")
