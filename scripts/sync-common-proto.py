#!/usr/bin/env python3
"""Copy or check the public proto snapshot bundled in flare-proto."""

import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BINDINGS = ROOT / "crates/flare-proto"
SNAPSHOT = BINDINGS / "proto"
PIN = BINDINGS / "proto-source-revision"


def git(source, *args):
    return subprocess.check_output(["git", "-C", source, *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT.parent / "flare-protocol")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--revision", help="Git commit or tag to copy into the binding")
    args = parser.parse_args()

    revision = PIN.read_text().strip() if args.check else args.revision
    commit = git(args.source, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode().strip()
    files = git(args.source, "ls-tree", "--name-only", commit + ":proto").decode().splitlines()
    expected = {
        name: git(args.source, "show", f"{commit}:proto/{name}")
        for name in files if name.endswith(".proto")
    }
    if not expected:
        raise SystemExit("The selected revision has no shared .proto files")
    current = {path.name: path.read_bytes() for path in SNAPSHOT.glob("*.proto")}
    if args.check:
        if current != expected:
            raise SystemExit(f"Shared .proto snapshot differs from {commit}")
        print(f"Verified {len(expected)} shared .proto files from {commit}")
        return

    SNAPSHOT.mkdir(exist_ok=True)
    for name in current.keys() - expected.keys():
        (SNAPSHOT / name).unlink()
    for name, contents in expected.items():
        (SNAPSHOT / name).write_bytes(contents)
    PIN.write_text(commit + "\n")


if __name__ == "__main__":
    main()
