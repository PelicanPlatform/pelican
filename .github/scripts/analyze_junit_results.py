"""
Analyze JUnit XML artifacts from GitHub Actions workflow runs.

Reads JUnit XML files from the "artifacts/" directory and writes a summary of
test failures to "test-failure-analysis.txt".
"""

import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

# Track failures by matrix variant.
failures_by_matrix = defaultdict(lambda: defaultdict(int))

# Find all JUnit XML files.
artifacts_dir = Path("artifacts")
if not artifacts_dir.exists():
    print("No artifacts directory found")
    sys.exit(0)

for run_dir in sorted(artifacts_dir.iterdir()):
    if not run_dir.is_dir():
        continue

    # Process each matrix variant.
    for artifact_dir in run_dir.iterdir():
        if not artifact_dir.is_dir() or not artifact_dir.name.startswith("junit-"):
            continue

        # Extract the matrix variant name by stripping the "junit-" prefix and
        # the OS suffix (e.g., "junit-pelican-Linux" -> "pelican").
        matrix_name = artifact_dir.name.removeprefix("junit-")
        for os_suffix in ("-Linux", "-macOS", "-Windows"):
            matrix_name = matrix_name.removesuffix(os_suffix)

        # Find JUnit XML files.
        for xml_file in artifact_dir.glob("*.xml"):
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()

                # Parse test cases.
                for testcase in root.iter("testcase"):
                    test_name = f"{testcase.get('classname').split('/')[-1]}.{testcase.get('name')}"

                    # Check if the test failed.
                    if (
                        testcase.find("failure") is not None
                        or testcase.find("error") is not None
                    ):
                        failures_by_matrix[matrix_name][test_name] += 1
            except Exception as e:
                print(f"Error parsing {xml_file}: {e}")

# Write results to file.
with open("test-failure-analysis.txt", "w", encoding="utf-8") as f:
    for matrix_name in sorted(failures_by_matrix.keys()):
        f.write(f"### {matrix_name}\n\n")

        failures = failures_by_matrix[matrix_name]
        if not failures:
            f.write("No failures found\n\n")
            continue

        # Sort by failure count (descending), then by test name.
        sorted_failures = sorted(failures.items(), key=lambda x: (-x[1], x[0]))

        f.write(f"{len(failures)} tests with failures:\n\n")

        for test_name, count in sorted_failures:
            f.write(f"- {count} failures: {test_name}\n\n")

print("Analysis complete. Results written to test-failure-analysis.txt.")
