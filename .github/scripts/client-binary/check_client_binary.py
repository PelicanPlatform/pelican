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
"size" target the GOOS and GOARCH in the environment (default: the
host's).

deps
  Fails if the client depends on a package from this module that is not
  listed in client_packages.txt, for any OS that GoReleaser builds the
  client for. For each such package that the client can reach without
  going through another, prints a shortest chain of imports to it and
  the other unlisted packages that it brings in. Also fails if an entry
  names a package that the client does not depend on for any of those
  OSes, which catches typos and entries that have gone stale. Ignores
  third-party packages.

reflect
  Fails if the client binary can call methods by name via reflection, as
  text/template does. The linker normally drops methods that nothing
  calls. But if any reachable code can call methods by name, the linker
  must keep every exported method of every reachable type. Prints chains
  of references that lead to the likely causes.

size
  Builds the client from the working tree and from the given commit.
  Fails if the binary grew by more than the given percentage
  (default: 5). This is a backstop for growth that the other checks miss.
  With --warn-only, warns about such growth instead of failing. For such
  growth, also prints the likely causes: each import that brings new
  packages into the client and the packages already in the client that
  grew the most. For each such import, prints the files that contain it.
  If the client does not build from the given commit, warns and passes.
  Still fails if it cannot download the modules that the commit requires.

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
# and whether it is a Git checkout. They do not affect which code the linker
# keeps.
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

IN_GITHUB_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"


def shell_command(args: list[str], env: dict[str, str]) -> str:
    """Return a shell command that runs a command with variables set
    in its environment.
    """
    return " ".join([*(f"{name}={shlex.quote(value)}" for name, value in env.items()), shlex.join(args)])


class CommandError(Exception):
    """A command failed. The code that raises this has already printed
    the command's error output.

    Args:
        command: The command and its arguments.
        env: The variables set in its environment, beyond os.environ.
        cwd: The directory it ran in.
    """

    def __init__(self, command: list[str], env: dict[str, str], cwd: Path):
        super().__init__(f"This command failed in {cwd}: {shell_command(command, env)}")


def annotate(level: str, message: str) -> None:
    """Print a message to stderr, as an annotation in GitHub Actions.

    Args:
        level: The message's severity, "error" or "warning".
        message: The message.
    """
    if IN_GITHUB_ACTIONS:
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


def run(args: list[str], env: dict[str, str] | None = None, cwd: Path = REPO_ROOT) -> str:
    """Run a command and return its stdout.

    If the command fails, prints its stderr and raises CommandError.

    Args:
        args: The command and its arguments.
        env: Variables to set in its environment, beyond os.environ.
        cwd: The directory to run it in.
    """
    env = env or {}
    proc = subprocess.run(args, cwd=cwd, env=os.environ | env, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise CommandError(args, env, cwd)
    return proc.stdout


def run_go(args: list[str], env: dict[str, str] | None = None, cwd: Path = REPO_ROOT) -> str:
    """Run the go command with GO_ENV in its environment, as run() does."""
    return run(["go", *args], GO_ENV | (env or {}), cwd)


@functools.cache
def platform() -> str:
    """Return the target platform, as "GOOS/GOARCH"."""
    return "/".join(run_go(["env", "GOOS", "GOARCH"]).split())


def platform_env(target: str) -> dict[str, str]:
    """Return the environment variables that select a platform,
    "GOOS/GOARCH".
    """
    goos, goarch = target.split("/")
    return {"GOOS": goos, "GOARCH": goarch}


def build_args(out: Path, ldflags: str = LDFLAGS) -> list[str]:
    """Return the go command's arguments that build the client."""
    return ["build", *BUILD_ARGS, "-ldflags", ldflags, "-o", str(out), PACKAGE_DIR]


def build(out: Path, target: str, cwd: Path = REPO_ROOT, ldflags: str = LDFLAGS) -> int:
    """Build the client and return its size.

    Args:
        out: The path to write the binary to.
        target: The platform, as "GOOS/GOARCH".
        cwd: The root of the source tree.
        ldflags: The linker flags.
    """
    run_go(build_args(out, ldflags), platform_env(target), cwd)
    return out.stat().st_size


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

    # A shortest chain of imports that leads to the package without going
    # through another disallowed package, for the first platform
    # for which it is an entry point.
    chain: list[str]
    # The platforms for which it is an entry point.
    platforms: list[str] = dataclasses.field(default_factory=list[str])
    # The disallowed packages that it imports directly or indirectly,
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


def join_or(items: list[str]) -> str:
    """Join items into a list in English, such as "a, b, or c"."""
    if len(items) <= 2:
        return " or ".join(items)
    return ", ".join(items[:-1]) + ", or " + items[-1]


def relative(package: str) -> str:
    """Return a package's import path, relative to the module root."""
    return package.removeprefix(MODULE + "/")


def go_list(field: str, args: list[str], target: str, cwd: Path = REPO_ROOT) -> dict[str, list[str]]:
    """Return a list-valued field of each package that "go list" lists.

    Args:
        field: The field, such as "Imports".
        args: The packages to list, and any flags.
        target: The platform, as "GOOS/GOARCH".
        cwd: The root of the source tree.
    """
    template = "{{.ImportPath}} {{join ." + field + ' " "}}'
    output = run_go(["list", *BUILD_ARGS, "-f", template, *args], platform_env(target), cwd)
    result: dict[str, list[str]] = {}
    for line in output.splitlines():
        package, *values = line.split()
        result[package] = values
    return result


def import_graph(target: str, cwd: Path = REPO_ROOT) -> ImportGraph:
    """Return the client's import graph for a platform, "GOOS/GOARCH".

    The graph includes cmd.
    """
    return go_list("Imports", ["-deps", PACKAGE_DIR], target, cwd)


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


def first_importers(graph: ImportGraph, stop: set[str]) -> dict[str, str]:
    """Search the client's import graph breadth-first from cmd.

    Args:
        graph: The client's import graph.
        stop: The packages not to search past.

    Returns:
        A map from each package reached to the package
        through which the search first reached it, in the order reached.
    """
    importers: dict[str, str] = {}
    queue = collections.deque([CMD_PACKAGE])
    while queue:
        package = queue.popleft()
        for imported in graph[package]:
            if imported not in importers:
                importers[imported] = package
                if imported not in stop:
                    queue.append(imported)
    return importers


def entry_point_chains(graph: ImportGraph, disallowed: set[str]) -> dict[str, list[str]]:
    """Return a chain of imports to each entry point.

    Args:
        graph: The client's import graph for a platform.
        disallowed: The packages in the graph that are not allowed.

    Returns:
        A map from each entry point to a shortest chain of imports from cmd
        to it that does not go through another disallowed package.
    """
    # Since the search does not pass through disallowed packages,
    # each one that it reaches is an entry point, and its chain
    # is a shortest one that does not go through another.
    importers = first_importers(graph, disallowed)
    chains: dict[str, list[str]] = {}
    for entry_point in importers.keys() & disallowed:
        chain = [entry_point]
        while chain[-1] != CMD_PACKAGE:
            chain.append(importers[chain[-1]])
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
        # cmd is the client itself, not one of its dependencies.
        first_party = {p for p in graph if is_first_party(p)} - {CMD_PACKAGE}
        used |= first_party
        disallowed_here = first_party - allowed
        disallowed |= disallowed_here
        for package, chain in entry_point_chains(graph, disallowed_here).items():
            entry = entry_points.setdefault(package, EntryPoint(chain))
            entry.platforms.append(target)
            entry.brought_in |= reachable(graph, package) & disallowed_here

    platforms = join_or(DEPS_PLATFORMS)

    if disallowed:
        error(
            f"The client depends on {len(disallowed)} packages from this module that are"
            f" not listed in {ALLOW_LIST.name}. For each one that the client can reach without"
            " going through another, this check prints a chain of imports that leads to it."
            " After each chain, it lists the other unlisted packages that the package brings"
            " in. If the client should depend on one of these packages, add it to the list."
            " Otherwise, change the imports. For example, move the types that the client needs"
            " into server_structs."
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
            f" depend on for {platforms}. Remove them: {', '.join(stale)}"
        )

    if disallowed or stale:
        return 1
    print(
        f"All {len(used)} packages from this module that the client depends on"
        f" for {platforms} are listed in {ALLOW_LIST.name}."
    )
    return 0


# ---------------------------------------------------------------------------
# reflect

# The flags that the linker's -dumpdep output appends to a symbol's name.
DUMPDEP_FLAGS = re.compile(r" (<[A-Za-z]+>)+$")

# The most chains that "reflect" prints.
MAX_CHAINS = 5

# The go command's arguments for the build that "reflect" inspects.
REFLECT_BUILD_ARGS = build_args(Path(os.devnull), LDFLAGS + " -dumpdep")


def split_flags(field: str) -> tuple[str, str]:
    """Split a symbol in -dumpdep's output into its name and its flags."""
    match = DUMPDEP_FLAGS.search(field)
    return (field[: match.start()], match.group()) if match else (field, "")


def is_reflect_type(symbol: str) -> bool:
    """Return whether a symbol is one of reflect's own types."""
    return symbol.startswith(("type:reflect.", "type:*reflect."))


def dump_dependencies() -> str:
    """Build the client with -dumpdep and return the linker's output.

    If the build fails, prints its error output and raises CommandError.
    The printed output omits the dependencies that the linker prints
    for -dumpdep.
    """
    command = ["go", *REFLECT_BUILD_ARGS]
    # The go command prints the linker's output to its stderr.
    proc = subprocess.run(
        command, cwd=REPO_ROOT, env=os.environ | GO_ENV, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        sys.stderr.writelines(line for line in proc.stderr.splitlines(keepends=True) if " -> " not in line)
        raise CommandError(command, GO_ENV, REPO_ROOT)
    return proc.stderr


def check_reflect(_args: argparse.Namespace) -> int:
    """Run the "reflect" check and return the exit status."""
    output = dump_dependencies()

    # With -dumpdep, the linker prints a line "<parent> -> <symbol>"
    # as it marks each symbol reachable. The parent is "_" for a root.
    # The linker marks a type symbol again if the symbol gains <UsedInIface>
    # after the linker first marks it. The second parent can differ
    # from the first. Keep the first parent, so that each chain shows
    # how the linker first reached the symbol.
    parents: dict[str, str] = {}
    flagged: list[str] = []
    # Any real build has symbols flagged <UsedInIface>. If none are,
    # the format of the flags has likely changed, and flagged
    # would be empty.
    used_in_iface = False
    for line in output.splitlines():
        parent, sep, symbol = line.partition(" -> ")
        if not sep:
            continue
        name, flags = split_flags(symbol)
        parents.setdefault(name, split_flags(parent)[0])
        if "<ReflectMethod>" in flags:
            flagged.append(name)
        if "<UsedInIface>" in flags:
            used_in_iface = True

    if not parents or not used_in_iface:
        error(
            "The linker printed no dependencies for -dumpdep, or no symbols"
            " flagged <UsedInIface>. The format of its output may have changed."
        )
        return 1

    if not flagged:
        print(f"The client binary for {platform()} cannot call methods by name via reflection.")
        return 0

    error(
        f"The client binary for {platform()} can call methods by name via reflection,"
        " so the linker must keep every exported method of every reachable type."
        " The cause is often text/template, which Cobra uses for custom help and usage"
        " templates. Remove what reaches the symbol at the end of each chain of references"
        " that this check prints."
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
    # Most flagged symbols are methods that the linker keeps
    # only because some other flagged symbol is reachable. Their parent
    # is their type. The likely causes are those reached any other way.
    causes = [s for s in flagged if not parents[s].startswith("type:")] or flagged

    chains: list[list[str]] = []
    for symbol in causes:
        # The linker marks a symbol's first parent before the symbol,
        # so the chain cannot loop.
        chain = [symbol]
        while (parent := parents.get(chain[-1], "_")) != "_":
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
    command = shell_command(["go", *REFLECT_BUILD_ARGS], GO_ENV | platform_env(platform()))
    print(
        f"\nTo list all {len(flagged)} flagged symbols, run: {command} 2>&1 | grep -- '-> .*<ReflectMethod>'"
    )


# ---------------------------------------------------------------------------
# size

# The most causes that "size" reports.
MAX_CAUSES = 5
# The most packages already in the client that "size" reports as grown.
MAX_GROWN = 5
# The most of each cause's new packages that "size" lists.
MAX_BROUGHT_IN = 3

# The smallest change that "size" reports on a line of its own, ~0.01 MiB.
MIN_REPORTED_CHANGE = 2**20 // 100

# The indentation of each line in the report after an item's first,
# which aligns it past the column of sizes.
REPORT_INDENT = " " * 12


def git(*args: str) -> str:
    """Run git in the repository and return its stripped stdout."""
    return run(["git", *args]).strip()


def export_commit(commit: str, dest: Path) -> None:
    """Write the files in a commit to a new directory.

    Args:
        commit: The commit.
        dest: The directory. Also writes an archive of the commit
            next to it, with the same name plus ".tar".
    """
    # Export the commit rather than adding a worktree,
    # which would stay registered in the repository if this process
    # were killed.
    archive = dest.with_name(dest.name + ".tar")
    git("archive", "--output", str(archive), commit)
    with tarfile.open(archive) as tar:
        tar.extractall(dest, filter="data")


def mib(size: int) -> str:
    """Return a size in bytes, formatted in MiB."""
    return f"{size / 2**20:.2f} MiB"


def mib_change(change: int) -> str:
    """Return a change in size in bytes, formatted in MiB with a sign."""
    return f"{change / 2**20:+.2f} MiB"


def describe_build(head: str, clean: bool) -> str:
    """Return a Markdown description of the build, for the table of sizes.

    Args:
        head: The commit that is checked out.
        clean: Whether the working tree matches it.
    """
    if not clean:
        return "working tree"
    # A shallow clone lacks the parents themselves, so read their IDs
    # from the commit object.
    header = git("cat-file", "-p", head).split("\n\n", 1)[0]
    parents = [line.split()[1] for line in header.splitlines() if line.startswith("parent ")]
    if len(parents) == 2:
        # For a pull request, this is GitHub's test merge commit,
        # which the author does not have.
        return f"`{parents[1][:12]}` merged into `{parents[0][:12]}`"
    return f"`{head[:12]}`"


def append_summary(markdown: str) -> None:
    """In GitHub Actions, append Markdown to the job summary."""
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(markdown)


def print_sizes(title: str, rows: list[tuple[str, str, str]]) -> None:
    """Print a table of binary sizes.

    In GitHub Actions, also add the table to the job summary.

    Args:
        title: The table's title.
        rows: Each row's label, commit, and size. The commit is in Markdown.
    """
    print(f"{title}:")
    for label, commit, size in rows:
        print(f"  {label + ':':<12} {size:<22} {commit.replace('`', '')}")

    table = [f"### {title}\n", "| | Commit | Size |", "| --- | --- | --- |"]
    for label, commit, size in rows:
        table.append(f"| {label} | {commit} | {size} |")
    append_summary("\n".join(table) + "\n\n")


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

    Searches the import graph breadth-first from cmd. Where the search
    first reaches a new package from one that is not new, that import
    is a cause. Attributes any other new package to the cause of the package
    from which the search first reaches it.

    Args:
        graph: The client's import graph.
        new: The packages in the graph that the reference's graph lacks.
    """
    causes: list[Cause] = []
    cause_of: dict[str, Cause] = {}
    for package, importer in first_importers(graph, set()).items():
        if package in new:
            if importer in new:
                # The search reached the importer first, so it already has a cause.
                cause = cause_of[importer]
            else:
                cause = Cause(importer, package)
                causes.append(cause)
            cause.brought_in.append(package)
            cause_of[package] = cause
    return causes


def symbol_package(symbol: str) -> str:
    """Return the import path in a symbol's name.

    Returns "" if the name has none. The result
    is not necessarily a package: for "go:string.*", it is "go:string".
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
        packages: The packages to count. Ignores symbols named
            for any other package or for none.
    """
    sizes: collections.Counter[str] = collections.Counter()
    for line in run_go(["tool", "nm", "-size", str(binary)]).splitlines():
        # Skip undefined symbols, which have no address. Also skip BSS,
        # which takes up no space in the file.
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
        A map from each package to its files,
        relative to the repository root.
    """
    # Given no packages, "go list" lists the one in the current directory.
    if not packages:
        return {}
    files = go_list("GoFiles", packages, target)
    return {p: [f"{relative(p)}/{name}" for name in names] for p, names in files.items()}


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


@dataclasses.dataclass
class Growth:
    """How the client's packages changed, relative to the reference's."""

    # This build's import graph.
    graph: ImportGraph
    # The packages in that graph that the reference's lacks.
    new: set[str]
    # How much each package's share of the binary changed, in bytes.
    # It covers every package in either build except the runtime.
    sizes: dict[str, int]

    def added_by(self, cause: Cause) -> int:
        """Return how much a cause added to the binary, in bytes."""
        return sum(self.sizes[p] for p in cause.brought_in)


def measure_growth(target: str, ref_tree: Path, tmp: Path) -> Growth:
    """Return how the client's packages changed.

    Args:
        target: The platform, as "GOOS/GOARCH".
        ref_tree: The root of the reference commit's source tree.
        tmp: A directory to write binaries to.
    """
    # Keep the symbol table, which "go tool nm" needs.
    ldflags = shlex.join(flag for flag in shlex.split(LDFLAGS) if flag != "-s")
    new_binary = tmp / "pelican-new-symbols"
    ref_binary = tmp / "pelican-ref-symbols"
    build(new_binary, target, REPO_ROOT, ldflags)
    build(ref_binary, target, ref_tree, ldflags)
    new_graph = import_graph(target)
    ref_graph = import_graph(target, ref_tree)
    # Mach-O and PE record no symbol sizes, so "go tool nm" takes
    # each symbol's size to be the distance to the next one.
    # The runtime's symbols that mark where its tables start
    # then take in whole tables. Leave the runtime out, so that it counts
    # as not attributed.
    packages = (new_graph.keys() | ref_graph.keys()) - {"runtime"}
    new_sizes = package_sizes(new_binary, packages)
    ref_sizes = package_sizes(ref_binary, packages)
    return Growth(
        graph=new_graph,
        new=new_graph.keys() - ref_graph.keys(),
        sizes={p: new_sizes[p] - ref_sizes[p] for p in packages},
    )


def cause_lines(cause: Cause, growth: Growth, files: dict[str, list[str]], changed: set[str]) -> list[str]:
    """Return the lines of the report on the causes of growth for a cause.

    Args:
        cause: The cause.
        growth: How the client's packages changed.
        files: The Go files in each package that imports a cause's package.
        changed: The files that differ from the reference's.
    """
    lines = [
        f"{mib_change(growth.added_by(cause)):>10}"
        f"  {relative(cause.importer)} now imports {relative(cause.imported)}"
    ]
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
        (c for c in growth_causes(growth.graph, growth.new) if growth.added_by(c) >= MIN_REPORTED_CHANGE),
        key=growth.added_by,
        reverse=True,
    )[:MAX_CAUSES]
    grown = sorted(
        (p for p in growth.sizes.keys() - growth.new if growth.sizes[p] >= MIN_REPORTED_CHANGE),
        key=lambda p: growth.sizes[p],
        reverse=True,
    )[:MAX_GROWN]
    importers = sorted({c.importer for c in causes if is_first_party(c.importer)})
    files = go_files(importers, target)
    changed = changed_files(reference)

    lines: list[str] = []
    for cause in causes:
        lines += cause_lines(cause, growth, files, changed)
    lines += [
        f"{mib_change(growth.sizes[p]):>10}  {relative(p)} grew (already in the binary)" for p in grown
    ]
    attributed = sum(growth.sizes.values())
    shown = sum(growth.added_by(c) for c in causes) + sum(growth.sizes[p] for p in grown)
    lines.append(f"{mib_change(attributed - shown):>10}  other packages")
    lines.append(
        f"{mib_change(change - attributed):>10}  not attributed to a package"
        " (mostly function and type metadata, which grows with code)"
    )
    return lines


def explain_growth(target: str, reference: str, ref_tree: Path, tmp: Path, change: int) -> None:
    """Print the likely causes of the client binary's growth.

    In GitHub Actions, also add them to the job summary. If finding them
    fails, warns instead.

    Args:
        target: The platform, as "GOOS/GOARCH".
        reference: The reference commit.
        ref_tree: The root of the reference commit's source tree.
        tmp: A directory to write binaries to.
        change: How much the binary grew, in bytes.
    """
    try:
        lines = growth_report(measure_growth(target, ref_tree, tmp), target, reference, change)
    except CommandError as e:
        warning(f"Cannot find the likely causes of the growth. {e}")
        return

    title = f"Likely Causes of the Growth for {target}"
    print(f"\n{title}:")
    print("\n".join(lines))
    append_summary(f"### {title}\n\n```text\n" + "\n".join(lines) + "\n```\n\n")


def print_repro_command(target: str, head: str, reference: str, max_growth_percent: float) -> None:
    """Print commands that repeat the "size" check's comparison."""
    script = str(Path(__file__).resolve().relative_to(REPO_ROOT))
    args = [script, "size", "--reference", reference, "--max-growth-percent", f"{max_growth_percent:g}"]
    print("\nTo repeat this comparison, run:")
    if IN_GITHUB_ACTIONS:
        print(f"  git fetch origin {head} && git switch --detach FETCH_HEAD")
    print(f"  {shell_command(args, platform_env(target))}")


def check_size(args: argparse.Namespace) -> int:
    """Run the "size" check and return the exit status."""
    reference = git("rev-parse", "--verify", args.reference + "^{commit}")
    head = git("rev-parse", "HEAD")
    clean = not git("status", "--porcelain")
    target = platform()
    if reference == head and clean:
        print(f"Reference commit {reference[:12]} is what would be built, so there is nothing to compare.")
        return 0

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        ref_tree = tmp / "reference"
        new_size = build(tmp / "pelican-new", target)
        export_commit(reference, ref_tree)
        # Download the modules separately. Otherwise, a network error
        # or other download failure would look like a reference
        # that does not build.
        try:
            run_go(["mod", "download"], cwd=ref_tree)
        except CommandError:
            error(
                f"Cannot download the modules that reference commit {reference[:12]} requires."
                " If the cause is transient, such as a network error, run the check again."
            )
            return 1
        try:
            ref_size = build(tmp / "pelican-ref", target, ref_tree)
        except CommandError:
            # Failing would blame the change for the reference's breakage,
            # even when the change is what repairs it.
            warning(
                f"The client does not build from reference commit {reference[:12]}."
                " There is nothing to compare with."
            )
            return 0

        change = new_size - ref_size
        percent = 100 * change / ref_size
        rows = [
            ("Reference", f"`{reference[:12]}`", mib(ref_size)),
            ("This build", describe_build(head, clean), mib(new_size)),
            ("Change", "", f"{mib_change(change)} ({percent:+.1f}%)"),
        ]
        print_sizes(f"Client Binary Size for {target}", rows)
        if percent <= args.max_growth_percent:
            return 0

        message = (
            f"The client binary for {target} grew by {percent:.1f}%, more than the"
            f" {args.max_growth_percent:g}% allowed."
        )
        if args.warn_only:
            warning(message)
        elif IN_GITHUB_ACTIONS:
            error(
                f"{message} If the growth is expected, explain why in the pull request,"
                " add the client-growth-expected label, and re-run the failed jobs."
            )
        else:
            error(message)
        explain_growth(target, reference, ref_tree, tmp, change)
        print_repro_command(target, head, reference, args.max_growth_percent)
        return 0 if args.warn_only else 1


# ---------------------------------------------------------------------------
# config

# The keys of GoReleaser's build that "config" recognizes. It compares
# those that can change the binary for a given architecture. An unknown key
# might change it too. Examples are "overrides" and "gcflags".
KNOWN_BUILD_KEYS = {"id", "env", "goos", "goarch", "dir", "binary", "tags", "ldflags", "ignore"}


def load_yaml(path: Path) -> Any:
    """Return the contents of a YAML file, as parsed by yq."""
    return json.loads(run(["yq", "-o", "json", ".", str(path)]))


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
    # GoReleaser joins the entries into one string of flags.
    # Remove the version metadata, which does not affect the checks:
    # each "-X" and its value.
    ldflags = shlex.split(" ".join(goreleaser_build.get("ldflags", [])))
    while "-X" in ldflags:
        i = ldflags.index("-X")
        del ldflags[i : i + 2]
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
    mismatches = [
        (setting, goreleaser, checks) for setting, goreleaser, checks in settings if goreleaser != checks
    ]
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
    # Python block-buffers stdout when it is a pipe, as it is in CI.
    # It line-buffers stderr. Without line buffering, the details printed
    # to stdout would come out after the errors that introduce them.
    cast(io.TextIOWrapper, sys.stdout).reconfigure(line_buffering=True)
    try:
        return args.func(args)
    except CommandError as e:
        error(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
