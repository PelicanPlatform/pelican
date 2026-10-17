#!/usr/bin/env python3
#
# Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You may
# obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Print the floating container image tag that a release tag should get.

Usage: git tag -l | floating_image_tags.py v26.1.0

The floating tags are:

  - "latest", for the highest release before v26;
  - "vN.0", for the highest vN.0.z, with N >= 26; and
  - "vN.x", for the highest vN.y.z, with N >= 26 and y >= 1.

The given tag gets its floating tag, unless one of the existing tags, read
from stdin, is a newer release that would get the same one. Prints nothing
for anything other than a vX.Y.Z tag, e.g., a release candidate.
"""

import re
import sys


def parse(tag):
    """Return (X, Y, Z) for the release tag "vX.Y.Z", or None."""
    m = re.fullmatch(r"v([0-9]+)\.([0-9]+)\.([0-9]+)", tag)
    return tuple(int(n) for n in m.groups()) if m else None


def floating_tag(version):
    """Return the floating tag for the release (X, Y, Z)."""
    major, minor, _ = version
    if major < 26:
        return "latest"
    if minor == 0:
        return f"v{major}.0"
    return f"v{major}.x"


def main():
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {sys.argv[0]} <tag>")

    version = parse(sys.argv[1])
    if not version:
        return

    floating = floating_tag(version)
    existing = [v for v in map(parse, sys.stdin.read().split()) if v]

    if not any(floating_tag(v) == floating and v > version for v in existing):
        print(floating)


if __name__ == "__main__":
    main()
