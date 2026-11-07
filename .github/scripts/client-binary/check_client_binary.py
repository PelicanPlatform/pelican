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

"""Check the client binary for code that it should not contain.

Usage:

  check_client_binary.py deps
  check_client_binary.py reflect
  check_client_binary.py size --reference <commit> [--max-growth-percent <n>] [--warn-only]
  check_client_binary.py config

"deps", "reflect", and "size" build or inspect the client as GoReleaser
builds it: package ./cmd, with -tags client and CGO_ENABLED=0, from the
working tree as it is, including uncommitted changes. "reflect" and
"size" target the GOOS and GOARCH in the environment (by default, the
host's).

deps
  Fails if, for any OS that the client is released for, the client
  depends on a package from this module that is not listed in
  client_packages.txt. For each such package that the client can reach
  without going through another, prints a shortest chain of imports that
  leads to it and the others that it brings in. Also fails if an entry
  names a package that the client does not depend on for any of those
  OSes, which catches typos and entries that have gone stale. Third-party
  packages are not checked.

reflect
  Fails if the client binary can call methods by name via reflection, as
  text/template does. The linker normally drops methods that nothing
  calls, but if any reachable code can call methods by name, it must keep
  every exported method of every reachable type. Prints chains of
  references that lead to the likely causes.

size
  Builds the client both from the working tree and from the given commit,
  and fails if the binary grew by more than the given percentage (5 by
  default). This is a backstop for growth that the other checks miss.
  With --warn-only, it warns about such growth instead of failing. If the
  client does not build from the given commit, it warns and passes.
  For such growth, also prints the likely causes: each import that brings
  new packages into the client, with the files that contain it, and the
  packages already in the client that grew the most.

config
  Fails if the other checks no longer build the client as GoReleaser
  does: if this script's build settings or the OSes that it and the
  workflow check differ from the "pelican" build in .goreleaser.in.yml,
  or if that build has settings that this check does not recognize.
  Requires yq.
"""

import argparse
import collections
import dataclasses
import functools
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parents[3]
ALLOW_LIST = Path(__file__).resolve().parent / "client_packages.txt"

GORELEASER_CONFIG = REPO_ROOT / ".goreleaser.in.yml"
WORKFLOW = REPO_ROOT / ".github/workflows/check-client-binary.yml"

MODULE = "github.com/pelicanplatform/pelican"
CMD_PACKAGE = MODULE + "/cmd"

# Mirror GoReleaser's build of the client binary,
# except for the version metadata in -ldflags. The "config" check fails
# if they differ. The extra flags -trimpath and -buildvcs=false keep
# the binary from depending on where the source tree is
# and whether it is a Git checkout, and they do not affect which code
# the linker keeps.
GORELEASER_BUILD_ID = "pelican"
GO_ENV = {"CGO_ENABLED": "0"}
PACKAGE_DIR = "./cmd"
TAGS = ["client"]
BUILD_ARGS = ["-tags", ",".join(TAGS), "-trimpath", "-buildvcs=false"]
LDFLAGS = "-s -w"

# The platforms for which "deps" checks the client's dependencies: every OS
# that GoReleaser builds the client for. The client's dependencies
# rarely differ by architecture.
DEPS_PLATFORMS = ["linux/amd64", "darwin/amd64", "windows/amd64"]


def go_env() -> dict[str, str]:
    """Return the environment in which to run the go command."""
    return dict(os.environ) | GO_ENV


def annotate(level: str, message: str) -> None:
    """Print a message to stderr, as an annotation in GitHub Actions.

    Args:
        level: The message's severity, "error" or "warning".
        message: The message.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true":
        # Workflow commands require these escapes.
        message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{level}::{message}", file=sys.stderr)
    else:
        print(f"{level}: {message}", file=sys.stderr)


def error(message: str) -> None:
    """Print an error message, as annotate() does."""
    annotate("error", message)


def warning(message: str) -> None:
    """Print a warning message, as annotate() does."""
    annotate("warning", message)


def run_go(args: list[str], env: dict[str, str] | None = None, cwd: Path = REPO_ROOT) -> str:
    """Run the go command and return its stdout, exiting if it fails.

    Args:
        args: The command's arguments.
        env: Variables to set in its environment, beyond those of go_env().
        cwd: The directory to run it in.
    """
    proc = subprocess.run(
        ["go", *args],
        cwd=cwd,
        env=go_env() | (env or {}),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        assignments = [f"{k}={shlex.quote(v)}" for k, v in (GO_ENV | (env or {})).items()]
        error(f"This command failed: {' '.join([*assignments, shlex.join(['go', *args])])}")
        sys.exit(1)
    return proc.stdout


@functools.cache
def platform() -> str:
    """Return the target platform, as "GOOS/GOARCH"."""
    return "/".join(run_go(["env", "GOOS", "GOARCH"]).split())


def build(out: Path, cwd: Path = REPO_ROOT, ldflags: str = LDFLAGS) -> tuple[int, str]:
    """Build the client from the source tree at cwd.

    Returns:
        The go command's exit status and its combined stdout and stderr.
    """
    proc = subprocess.run(
        ["go", "build", *BUILD_ARGS, "-ldflags", ldflags, "-o", str(out), PACKAGE_DIR],
        cwd=cwd,
        env=go_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout


def build_command(out: str, ldflags: str = LDFLAGS) -> str:
    """Return a shell command that builds the client as build() does."""
    goos, goarch = platform().split("/")
    env = " ".join(f"{name}={value}" for name, value in GO_ENV.items())
    return (
        f"{env} GOOS={goos} GOARCH={goarch}"
        f" go build {' '.join(BUILD_ARGS)} -ldflags='{ldflags}' -o {out} {PACKAGE_DIR}"
    )


# ---------------------------------------------------------------------------
# deps

# A map from each package to the packages that it imports.
ImportGraph = dict[str, list[str]]


@dataclasses.dataclass
class EntryPoint:
    """An entry point into the disallowed packages.

    An entry point is a disallowed package that the client can reach
    without going through another.
    """

    # A shortest chain of imports that leads to the package,
    # for the first platform for which it is an entry point.
    chain: list[str]
    # The platforms for which it is an entry point.
    platforms: list[str] = dataclasses.field(default_factory=list[str])
    # The disallowed packages that it imports, directly or indirectly,
    # for any of those platforms.
    brought_in: set[str] = dataclasses.field(default_factory=set[str])


def load_allow_list() -> set[str]:
    """Return the full import paths of the packages in the allow list."""
    allowed: set[str] = set()
    with open(ALLOW_LIST, encoding="utf-8") as f:
        for line in f:
            entry = line.split("#", 1)[0].strip()
            if entry:
                allowed.add(f"{MODULE}/{entry}")
    return allowed


def is_first_party(package: str) -> bool:
    """Return whether a package is from this module."""
    return package.startswith(MODULE + "/")


def relative(package: str) -> str:
    """Return a package's import path, relative to the module root."""
    return package.removeprefix(MODULE + "/")


def import_graph(target: str, cwd: Path = REPO_ROOT) -> ImportGraph:
    """Return the client's import graph for a platform.

    Args:
        target: The platform, as "GOOS/GOARCH".
        cwd: The root of the source tree.

    Returns:
        A map from each package in the client's dependency graph,
        including ./cmd itself, to the packages that it imports.
    """
    goos, goarch = target.split("/")
    output = run_go(
        ["list", "-deps", *BUILD_ARGS, "-f", '{{.ImportPath}} {{join .Imports " "}}', PACKAGE_DIR],
        env={"GOOS": goos, "GOARCH": goarch},
        cwd=cwd,
    )
    graph: ImportGraph = {}
    for line in output.splitlines():
        package, *imports = line.split()
        graph[package] = imports
    return graph


def reachable(graph: ImportGraph, package: str) -> set[str]:
    """Return the transitive imports of a package."""
    seen: set[str] = set()
    stack = [package]
    while stack:
        for imported in graph[stack.pop()]:
            if imported not in seen:
                seen.add(imported)
                stack.append(imported)
    return seen


def entry_point_chains(graph: ImportGraph, disallowed: set[str]) -> dict[str, list[str]]:
    """Return a shortest chain of imports to each entry point.

    Args:
        graph: The client's import graph for a platform.
        disallowed: The packages in the graph that are not allowed.

    Returns:
        A map from each entry point to a shortest chain of imports from cmd
        to it.
    """
    # Search breadth-first from cmd without passing
    # through disallowed packages, so that each disallowed package found
    # is an entry point and the first package found to import it
    # is on a shortest chain.
    importer: dict[str, str] = {}
    queue = collections.deque([CMD_PACKAGE])
    while queue:
        package = queue.popleft()
        for imported in graph[package]:
            if imported not in importer:
                importer[imported] = package
                if imported not in disallowed:
                    queue.append(imported)

    chains: dict[str, list[str]] = {}
    for entry_point in importer.keys() & disallowed:
        chain = [entry_point]
        while chain[-1] != CMD_PACKAGE:
            chain.append(importer[chain[-1]])
        chains[entry_point] = list(reversed(chain))
    return chains


def check_deps(_args: argparse.Namespace) -> int:
    """Run the "deps" check and return the exit status."""
    allowed = load_allow_list()
    used: set[str] = set()
    disallowed: set[str] = set()
    entry_points: dict[str, EntryPoint] = {}

    for target in DEPS_PLATFORMS:
        graph = import_graph(target)
        first_party = {p for p in graph if is_first_party(p)}
        used |= first_party
        disallowed_here = first_party - allowed
        disallowed |= disallowed_here
        for package, chain in entry_point_chains(graph, disallowed_here).items():
            entry = entry_points.setdefault(package, EntryPoint(chain))
            entry.platforms.append(target)
            entry.brought_in |= reachable(graph, package) & disallowed_here

    platforms = ", ".join(DEPS_PLATFORMS)

    if disallowed:
        error(
            f"The client depends on {len(disallowed)} packages from this module that are"
            f" not listed in {ALLOW_LIST.name}. Below, for each one that the client can reach"
            " without going through another, is a chain of imports that leads to it, followed"
            " by any others that the client depends on only through such packages. If the"
            " client should depend on a package below, add it to the list. Otherwise, change"
            " the imports below, for example, by moving the types that the client needs into"
            " server_structs."
        )
        for package, entry in sorted(entry_points.items()):
            print(f"\n# {relative(package)} ({', '.join(entry.platforms)})")
            print("\n".join(entry.chain))
            others = sorted(relative(p) for p in entry.brought_in - entry_points.keys())
            if others:
                print(f"# Also brought in by {relative(package)}:")
                print("\n".join(f"#   {p}" for p in others))
        print()

    stale = sorted(relative(p) for p in allowed - used)
    if stale:
        error(
            f"These entries in {ALLOW_LIST.name} name packages that the client does not"
            f" depend on ({platforms}). Remove them: {', '.join(stale)}"
        )

    if disallowed or stale:
        return 1
    print(
        f"All {len(used)} packages from this module that the client depends on"
        f" ({platforms}) are listed in {ALLOW_LIST.name}."
    )
    return 0


# ---------------------------------------------------------------------------
# reflect

# The flags that the linker's -dumpdep output appends to a symbol's name.
DUMPDEP_FLAGS = re.compile(r" (<[A-Za-z]+>)+$")

# The most chains that "reflect" prints.
MAX_CHAINS = 5


def symbol_name(field: str) -> str:
    """Return a symbol's name, without the flags that -dumpdep appends."""
    return DUMPDEP_FLAGS.sub("", field)


def is_reflect_type(symbol: str) -> bool:
    """Return whether a symbol is one of reflect's own types."""
    return symbol.startswith(("type:reflect.", "type:*reflect."))


def check_reflect(_args: argparse.Namespace) -> int:
    """Run the "reflect" check and return the exit status."""
    with tempfile.TemporaryDirectory() as tmp:
        returncode, output = build(Path(tmp) / "pelican", ldflags=LDFLAGS + " -dumpdep")

    # With -dumpdep, the linker prints a line "<parent> -> <symbol>"
    # as it marks each symbol reachable. The parent is "_" for a root.
    # A type symbol is marked again, possibly from another parent,
    # if it gains <UsedInIface> after it is first marked.
    # Keep the first parent, so that each chain shows how the linker
    # first reached the symbol. A symbol flagged <ReflectMethod> can call
    # methods by name, and if any such symbol is reachable, the linker keeps
    # every exported method of every reachable type.
    parents: dict[str, str] = {}
    flagged: list[str] = []
    other_lines: list[str] = []
    # Any real build has symbols flagged <UsedInIface>. If none are,
    # the format of the flags has likely changed, and flagged
    # would be empty.
    used_in_iface = False
    for line in output.splitlines():
        parent, sep, symbol = line.partition(" -> ")
        if not sep:
            other_lines.append(line)
            continue
        name = symbol_name(symbol)
        parents.setdefault(name, symbol_name(parent))
        match = DUMPDEP_FLAGS.search(symbol)
        flags = match.group(0) if match else ""
        if "<ReflectMethod>" in flags:
            flagged.append(name)
        if "<UsedInIface>" in flags:
            used_in_iface = True

    if returncode != 0:
        print("\n".join(other_lines[-50:]), file=sys.stderr)
        error("Building the client failed.")
        return 1
    if not parents or not used_in_iface:
        error(
            "The linker printed no dependencies for -dumpdep, or no symbols"
            " flagged <UsedInIface>. Has the format of its output changed?"
        )
        return 1

    if not flagged:
        print(f"The client binary ({platform()}) cannot call methods by name via reflection.")
        return 0

    error(
        f"The client binary ({platform()}) can call methods by name via reflection,"
        " so the linker must keep every exported method of every reachable type."
        " Remove what reaches the symbols below. The cause is often text/template,"
        " which Cobra uses for custom help and usage templates."
    )
    print_reflect_causes(parents, flagged)
    return 1


def print_reflect_causes(parents: dict[str, str], flagged: list[str]) -> None:
    """Print chains of references that lead to the likely causes.

    Args:
        parents: Each symbol mapped to the parent that the linker
            first marked it reachable from.
        flagged: The symbols flagged <ReflectMethod>.
    """
    # Most flagged symbols are methods that the linker kept
    # only because some other flagged symbol was reachable; their parent
    # is their type. The likely causes are those reached any other way.
    causes = [s for s in flagged if not parents[s].startswith("type:")] or flagged

    chains: list[list[str]] = []
    for symbol in causes:
        chain = [symbol]
        while (parent := parents.get(chain[-1], "_")) != "_" and len(chain) <= len(parents):
            chain.append(parent)
        chains.append(list(reversed(chain)))

    # A chain that passes through one of reflect's own types usually shows
    # only a side effect: a method of that type that calls methods by name,
    # kept because of some other cause.
    shown = [c for c in chains if not any(is_reflect_type(s) for s in c)] or chains
    hidden = len(chains) - min(len(shown), MAX_CHAINS)

    print("Each chain shows how the linker first reached the symbol, from a root.")
    for chain in shown[:MAX_CHAINS]:
        print(f"\n# {chain[-1]}")
        print("\n".join(chain))
    if hidden:
        print(f"\n({hidden} more chains not shown.)")
    print(
        f"\nTo list all {len(flagged)} flagged symbols, run:"
        f" {build_command('/dev/null', ldflags=LDFLAGS + ' -dumpdep')}"
        " 2>&1 | grep -- '-> .*<ReflectMethod>'"
    )


# ---------------------------------------------------------------------------
# size

# The most causes, and the most packages that grew in place, that "size"
# reports, and the most of each cause's new packages that it lists.
MAX_CAUSES = 5
MAX_GROWN = 5
MAX_BROUGHT_IN = 3

# The smallest change that "size" reports on a line of its own,
# about 0.01 MiB.
MIN_REPORTED_CHANGE = 2**20 // 100

# The indentation of each line in the report after an item's first,
# which aligns it past the column of sizes.
REPORT_INDENT = " " * 12


def git(*args: str) -> str:
    """Run git and return its stripped stdout, exiting if it fails."""
    proc = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        error(f'"git {" ".join(args)}" failed.')
        sys.exit(1)
    return proc.stdout.strip()


def export_commit(commit: str, dest: Path) -> None:
    """Write the files in a commit to a new directory.

    Args:
        commit: The commit.
        dest: The directory. An archive of the commit is written next to it,
            with the same name plus ".tar".
    """
    # Export the commit rather than adding a worktree,
    # which would stay registered in the repository if this process
    # were killed.
    archive = dest.with_name(dest.name + ".tar")
    git("archive", "--output", str(archive), commit)
    with tarfile.open(archive) as tar:
        tar.extractall(dest, filter="data")


def binary_size(out: Path, cwd: Path) -> int | None:
    """Build the client and return its size.

    If the build fails, prints the go command's output and returns None.

    Args:
        out: The path to write the binary to.
        cwd: The root of the source tree to build.
    """
    returncode, output = build(out, cwd=cwd)
    if returncode != 0:
        print(output, file=sys.stderr)
        return None
    return out.stat().st_size


def mib(size: int) -> str:
    """Return a size in bytes, formatted in MiB."""
    return f"{size / 2**20:.2f} MiB"


def mib_change(change: int) -> str:
    """Return a change in size in bytes, formatted in MiB with a sign."""
    return f"{change / 2**20:+.2f} MiB"


def describe_build(head: str, clean: bool) -> str:
    """Return what is being built, for the table of sizes.

    Args:
        head: The commit that is checked out.
        clean: Whether the working tree matches it.
    """
    if not clean:
        return "working tree"
    # A shallow clone lacks the parents themselves,
    # so read their IDs from the commit object.
    header = git("cat-file", "-p", head).split("\n\n", 1)[0]
    parents = [line.split()[1] for line in header.splitlines() if line.startswith("parent ")]
    if len(parents) == 2:
        # For a pull request, this is GitHub's test merge commit,
        # which the author does not have.
        return f"{parents[1][:12]} merged into {parents[0][:12]}"
    return head[:12]


def print_sizes(title: str, rows: list[tuple[str, str, str]]) -> None:
    """Print a table of binary sizes.

    In GitHub Actions, also add the table to the job summary.

    Args:
        title: The table's title.
        rows: Each row's label, commit, and size.
    """
    print(f"{title}:")
    for label, commit, size in rows:
        print(f"  {label + ':':<12} {size:<22} {commit}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### {title}\n\n")
            f.write("| | Commit | Size |\n| --- | --- | --- |\n")
            for label, commit, size in rows:
                commit = re.sub(r"\b[0-9a-f]{12}\b", r"`\g<0>`", commit)
                f.write(f"| {label} | {commit} | {size} |\n")
            f.write("\n")


@dataclasses.dataclass
class Cause:
    """An import that brings new packages into the client."""

    importer: str
    imported: str
    # The new packages that the client reaches first through this import,
    # starting with the imported package.
    brought_in: list[str] = dataclasses.field(default_factory=list[str])


def growth_causes(graph: ImportGraph, new: set[str]) -> list[Cause]:
    """Return the imports that bring new packages into the client.

    Searches the import graph breadth-first from cmd. Wherever a package
    that is not new imports one that is, that import is a cause. Each new
    package is attributed to the cause through which the search first
    reaches it.

    Args:
        graph: The client's import graph.
        new: The packages in the graph that the reference's graph lacks.
    """
    causes: list[Cause] = []
    cause_of: dict[str, Cause] = {}
    seen = {CMD_PACKAGE}
    queue = collections.deque([CMD_PACKAGE])
    while queue:
        package = queue.popleft()
        for imported in graph[package]:
            if imported in seen:
                continue
            seen.add(imported)
            queue.append(imported)
            if imported in new:
                cause = cause_of.get(package)
                if cause is None:
                    cause = Cause(package, imported)
                    causes.append(cause)
                cause.brought_in.append(imported)
                cause_of[imported] = cause
    return causes


def symbol_package(symbol: str) -> str:
    """Return the import path in a symbol's name.

    Returns "" if the name has none. The result is not necessarily a
    package: for "go:string.*", it is "go:string".
    """
    # Drop any type arguments, which can contain other packages' paths.
    name = symbol.split("[", 1)[0]
    # The path ends at the first dot after its last slash. The linker
    # escapes any dots in the path's last element,
    # as in "gopkg.in/yaml%2ev3".
    end = name.find(".", name.rfind("/") + 1)
    if end < 0:
        return ""
    package = urllib.parse.unquote(name[:end])
    return CMD_PACKAGE if package == "main" else package


def package_sizes(binary: Path, packages: set[str]) -> collections.Counter[str]:
    """Return how much of a binary's file each package takes up.

    Args:
        binary: The binary. It must have a symbol table.
        packages: The packages to count. Symbols named for any other
            package, or for none, are not counted.
    """
    sizes: collections.Counter[str] = collections.Counter()
    for line in run_go(["tool", "nm", "-size", str(binary)]).splitlines():
        # Skip undefined symbols, which have no address,
        # and BSS, which takes up no space in the file.
        match = re.match(r"\s*[0-9a-f]+\s+(\d+)\s+([TtRrDd])\s+(.+)$", line)
        if match and (package := symbol_package(match.group(3))) in packages:
            sizes[package] += int(match.group(1))
    return sizes


def go_files(packages: list[str], target: str) -> dict[str, list[str]]:
    """Return the Go files that the client's build uses in each package.

    Args:
        packages: Packages from this module.
        target: The platform, as "GOOS/GOARCH".

    Returns:
        A map from each package to its files, relative to the repository
        root.
    """
    goos, goarch = target.split("/")
    output = run_go(
        ["list", *BUILD_ARGS, "-f", '{{.ImportPath}} {{join .GoFiles " "}}', *packages],
        env={"GOOS": goos, "GOARCH": goarch},
    )
    files: dict[str, list[str]] = {}
    for line in output.splitlines():
        package, *names = line.split()
        files[package] = [f"{relative(package)}/{name}" for name in names]
    return files


def file_imports(path: Path, package: str) -> bool:
    """Return whether a Go file imports a package."""
    text = path.read_text(encoding="utf-8", errors="replace")
    # Imports come before any other declaration.
    end = re.search(r"^(func|type|var|const)\b", text, re.MULTILINE)
    pattern = rf'^\s*(import\s+)?([\w.]+\s+)?"{re.escape(package)}"'
    return re.search(pattern, text[: end.start() if end else None], re.MULTILINE) is not None


def changed_files(reference: str) -> set[str]:
    """Return the files that differ between a commit and the working tree.

    The files are relative to the repository root.
    """
    changed = git("diff", "--name-only", "--no-renames", reference).splitlines()
    untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
    return set(changed + untracked)


def link_with_symbols(out: Path, cwd: Path) -> bool:
    """Build the client with its symbol table, which "go tool nm" needs.

    Only the link step runs again, since the compiled packages are cached.
    If the build fails, prints the go command's output.

    Args:
        out: The path to write the binary to.
        cwd: The root of the source tree to build.

    Returns:
        Whether the build succeeded.
    """
    ldflags = shlex.join(flag for flag in shlex.split(LDFLAGS) if flag != "-s")
    returncode, output = build(out, cwd=cwd, ldflags=ldflags)
    if returncode != 0:
        print(output, file=sys.stderr)
    return returncode == 0


@dataclasses.dataclass
class Growth:
    """How the client's packages changed, relative to the reference's."""

    # This build's import graph.
    graph: ImportGraph
    # The packages in that graph that the reference's lacks.
    new: set[str]
    # How much each package's share of the binary changed, in bytes,
    # for every package in either build except the runtime.
    sizes: dict[str, int]


def measure_growth(target: str, ref_tree: Path, tmp: Path) -> Growth | None:
    """Return how the client's packages changed, or None if building fails.

    Args:
        target: The platform, as "GOOS/GOARCH".
        ref_tree: The root of the reference commit's source tree.
        tmp: A directory to write binaries to.
    """
    new_binary = tmp / "pelican-new-symbols"
    ref_binary = tmp / "pelican-ref-symbols"
    if not (link_with_symbols(new_binary, REPO_ROOT) and link_with_symbols(ref_binary, ref_tree)):
        return None
    new_graph = import_graph(target)
    ref_graph = import_graph(target, ref_tree)
    # Mach-O and PE record no symbol sizes, so "go tool nm" takes each
    # symbol's size to be the distance to the next one. The runtime's
    # symbols that mark where its tables start then take in whole tables.
    # Leave the runtime out, so that it counts as not attributed.
    packages = (new_graph.keys() | ref_graph.keys()) - {"runtime"}
    new_sizes = package_sizes(new_binary, packages)
    ref_sizes = package_sizes(ref_binary, packages)
    return Growth(
        graph=new_graph,
        new=new_graph.keys() - ref_graph.keys(),
        sizes={p: new_sizes[p] - ref_sizes[p] for p in packages},
    )


def cause_lines(
    size: int, cause: Cause, growth: Growth, files: dict[str, list[str]], changed: set[str]
) -> list[str]:
    """Return the lines of the report on the causes of growth for a cause.

    Args:
        size: How much the cause added, in bytes.
        cause: The cause.
        growth: How the client's packages changed.
        files: The Go files in each package that imports a cause's package.
        changed: The files that differ from the reference's.
    """
    lines = [f"{mib_change(size):>10}  {relative(cause.importer)} now imports {relative(cause.imported)}"]
    for path in files.get(cause.importer, []):
        if file_imports(REPO_ROOT / path, cause.imported):
            lines.append(f"{REPORT_INDENT}in {path}" + (" (changed)" if path in changed else ""))
    if len(cause.brought_in) > 1:
        largest = sorted(cause.brought_in, key=lambda p: growth.sizes[p], reverse=True)[:MAX_BROUGHT_IN]
        lines.append(f"{REPORT_INDENT}bringing in {len(cause.brought_in)} new packages, the largest:")
        lines += [f"{REPORT_INDENT}  {mib(growth.sizes[p]):>9}  {relative(p)}" for p in largest]
    return lines


def growth_report(growth: Growth, target: str, reference: str, change: int) -> list[str]:
    """Return the lines of the report on the causes of growth.

    Args:
        growth: How the client's packages changed.
        target: The platform, as "GOOS/GOARCH".
        reference: The reference commit.
        change: How much the binary grew, in bytes.
    """
    causes = sorted(
        ((sum(growth.sizes[p] for p in c.brought_in), c) for c in growth_causes(growth.graph, growth.new)),
        key=lambda item: item[0],
        reverse=True,
    )
    causes = [(size, c) for size, c in causes[:MAX_CAUSES] if size >= MIN_REPORTED_CHANGE]
    grown = sorted(
        (p for p in growth.sizes.keys() - growth.new if growth.sizes[p] >= MIN_REPORTED_CHANGE),
        key=lambda p: growth.sizes[p],
        reverse=True,
    )[:MAX_GROWN]
    importers = sorted({c.importer for _, c in causes if is_first_party(c.importer)})
    files = go_files(importers, target) if importers else {}
    changed = changed_files(reference)

    lines: list[str] = []
    for size, cause in causes:
        lines += cause_lines(size, cause, growth, files, changed)
    lines += [
        f"{mib_change(growth.sizes[p]):>10}  {relative(p)} grew (already in the binary)" for p in grown
    ]
    attributed = sum(growth.sizes.values())
    shown = sum(size for size, _ in causes) + sum(growth.sizes[p] for p in grown)
    lines.append(f"{mib_change(attributed - shown):>10}  other packages")
    # Most of the rest is the runtime's tables of functions and types,
    # which grow with the code above but are not named for its packages.
    lines.append(
        f"{mib_change(change - attributed):>10}  not attributed to a package"
        " (mostly function and type metadata, which grows with code)"
    )
    return lines


def explain_growth(target: str, reference: str, ref_tree: Path, tmp: Path, change: int) -> None:
    """Print the likely causes of the client binary's growth.

    In GitHub Actions, also add them to the job summary.

    Args:
        target: The platform, as "GOOS/GOARCH".
        reference: The reference commit.
        ref_tree: The root of the reference commit's source tree.
        tmp: A directory to write binaries to.
        change: How much the binary grew, in bytes.
    """
    growth = measure_growth(target, ref_tree, tmp)
    if growth is None:
        warning("Building the client with its symbol table failed. Cannot find the likely causes.")
        return
    lines = growth_report(growth, target, reference, change)

    title = f"Likely causes of the growth ({target})"
    print(f"\n{title}:")
    print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### {title}\n\n```text\n" + "\n".join(lines) + "\n```\n\n")


def print_repro_command(target: str, head: str, reference: str, max_growth_percent: float) -> None:
    """Print commands that repeat the "size" check's comparison."""
    goos, goarch = target.split("/")
    script = Path(__file__).resolve().relative_to(REPO_ROOT)
    print("\nTo repeat this comparison, run:")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"  git fetch origin {head} && git switch --detach FETCH_HEAD")
    print(
        f"  GOOS={goos} GOARCH={goarch} {script} size --reference {reference}"
        f" --max-growth-percent {max_growth_percent:g}"
    )


def check_size(args: argparse.Namespace) -> int:
    """Run the "size" check and return the exit status."""
    reference = git("rev-parse", "--verify", args.reference + "^{commit}")
    head = git("rev-parse", "HEAD")
    clean = not git("status", "--porcelain")
    target = platform()
    if reference == head and clean:
        print(f"The reference, {reference[:12]}, is what would be built. Nothing to compare.")
        return 0

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        ref_tree = tmp / "reference"
        new_size = binary_size(tmp / "pelican-new", REPO_ROOT)
        if new_size is None:
            error("Building the client from the working tree failed.")
            return 1
        export_commit(reference, ref_tree)
        ref_size = binary_size(tmp / "pelican-ref", ref_tree)
        if ref_size is None:
            # Failing would blame the change for the reference's breakage,
            # even when the change is what repairs it.
            warning(
                f"Building the client from the reference commit, {reference[:12]}, failed."
                " There is nothing to compare with."
            )
            return 0

        change = new_size - ref_size
        percent = 100 * change / ref_size
        rows = [
            ("Reference", reference[:12], mib(ref_size)),
            ("This build", describe_build(head, clean), mib(new_size)),
            ("Change", "", f"{mib_change(change)} ({percent:+.1f}%)"),
        ]
        print_sizes(f"Client binary size ({target})", rows)
        if percent <= args.max_growth_percent:
            return 0

        message = (
            f"The client binary ({target}) grew by {percent:.1f}%, more than the"
            f" {args.max_growth_percent:g}% allowed. Its likely causes are listed below."
        )
        if args.warn_only:
            warning(message)
        else:
            error(message + " If the growth is expected, explain why in the pull request.")
        explain_growth(target, reference, ref_tree, tmp, change)

    print_repro_command(target, head, reference, args.max_growth_percent)
    return 0 if args.warn_only else 1


# ---------------------------------------------------------------------------
# config

# The keys of GoReleaser's build that "config" accounts for.
# It does not compare "goarch" and "ignore", since the other checks each
# target a single architecture. Any other key, such as "overrides"
# or "gcflags", might change the binary.
KNOWN_BUILD_KEYS = {"id", "env", "goos", "goarch", "dir", "binary", "tags", "ldflags", "ignore"}


def load_yaml(path: Path) -> Any:
    """Return the contents of a YAML file, as parsed by yq."""
    proc = subprocess.run(["yq", "-o", "json", ".", str(path)], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        error(f"Cannot parse {path.name} with yq.")
        sys.exit(1)
    return json.loads(proc.stdout)


def check_config(_args: argparse.Namespace) -> int:
    """Run the "config" check and return the exit status."""
    config = load_yaml(GORELEASER_CONFIG)
    builds = config.get("builds", [])
    goreleaser_build = next((b for b in builds if b.get("id") == GORELEASER_BUILD_ID), None)
    if goreleaser_build is None:
        error(f'{GORELEASER_CONFIG.name} has no build with the ID "{GORELEASER_BUILD_ID}".')
        return 1
    jobs = load_yaml(WORKFLOW)["jobs"]

    # GoReleaser applies the top-level env to every build,
    # and the build's own env takes precedence over it.
    env = dict(entry.split("=", 1) for entry in config.get("env", []) + goreleaser_build.get("env", []))
    goos = sorted(goreleaser_build.get("goos", []))
    # GoReleaser joins the entries into one string of flags. Skip the version
    # metadata, which does not affect the checks: each "-X" and its value.
    ldflags: list[str] = []
    flags = iter(shlex.split(" ".join(goreleaser_build.get("ldflags", []))))
    for flag in flags:
        if flag == "-X":
            next(flags, None)
        else:
            ldflags.append(flag)
    # (setting, GoReleaser's value, the checks' value)
    settings = [
        ("env", env, GO_ENV),
        ("dir", goreleaser_build.get("dir"), PACKAGE_DIR),
        ("tags", sorted(goreleaser_build.get("tags", [])), sorted(TAGS)),
        ("ldflags", ldflags, shlex.split(LDFLAGS)),
        ("goos (DEPS_PLATFORMS)", goos, sorted({p.split("/", maxsplit=1)[0] for p in DEPS_PLATFORMS})),
    ]
    # Check every job with an OS matrix, including any added later.
    settings += [
        (f"goos ({WORKFLOW.name}, {name})", goos, sorted(job["strategy"]["matrix"]["goos"]))
        for name, job in jobs.items()
        if "goos" in job.get("strategy", {}).get("matrix", {})
    ]
    mismatches = [s for s in settings if s[1] != s[2]]
    unknown = sorted(goreleaser_build.keys() - KNOWN_BUILD_KEYS)

    if mismatches or unknown:
        error(
            f'The checks no longer build the client as the "{GORELEASER_BUILD_ID}" build in'
            f" {GORELEASER_CONFIG.name} does. Update {Path(__file__).name} and"
            f" {WORKFLOW.name} to match it."
        )
        for setting, goreleaser, checks in mismatches:
            print(f"  {setting}: GoReleaser has {goreleaser}, but the checks have {checks}.")
        if unknown:
            print(f"  GoReleaser has settings that the checks do not account for: {', '.join(unknown)}.")
        return 1
    print(f'The checks build the client as the "{GORELEASER_BUILD_ID}" build does.')
    return 0


# ---------------------------------------------------------------------------


def main() -> int:
    """Run the requested check and return the exit status."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="check", required=True)
    subparsers.add_parser("deps").set_defaults(func=check_deps)
    subparsers.add_parser("reflect").set_defaults(func=check_reflect)
    size = subparsers.add_parser("size")
    size.add_argument("--reference", required=True, help="the commit to compare against")
    size.add_argument(
        "--max-growth-percent",
        type=float,
        default=5,
        help="the most that the binary may grow, in percent (default: %(default)g)",
    )
    size.add_argument(
        "--warn-only", action="store_true", help="warn about too much growth instead of failing"
    )
    size.set_defaults(func=check_size)
    subparsers.add_parser("config").set_defaults(func=check_config)

    args = parser.parse_args()
    # Python block-buffers stdout when it is a pipe, as in CI,
    # but not stderr, so the details printed to stdout would come out
    # after the errors that introduce them.
    cast(io.TextIOWrapper, sys.stdout).reconfigure(line_buffering=True)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
