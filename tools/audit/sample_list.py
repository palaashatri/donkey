#!/usr/bin/env python3
"""Same-population decompiler measurement (docs/AUDIT.md, section "Same-population measurement").

Two modes, both run with `python3 -I`:

  sample_list.py write LIST.json [--per-binary N] [--seed S] [--cli PATH]
      Draws N (default 300) .text function starts per binary with a fixed seed, from the
      function starts that the given CLI finds on the current commit, and saves the list.

  sample_list.py measure LIST.json OUT.json [--cli PATH]
      Runs `decompile --json` once per binary (all functions) with the CLI, keeps the listed
      addresses, and records, for each, its status and whether its pseudocode carries the
      notes "outgoing call arguments and return values follow no modelled ABI" (call note) or
      "control flow not fully structured" (structure note). The same list measured on two
      commits gives the same functions in both.

Only system binaries are used: their files are identical at every commit, so the population is
the same by construction. A commit's own donkey-cli is a different file at each commit.
"""
import argparse, json, os, random, re, subprocess, sys

BINARIES = [
    ("/usr/bin/ls", "ls"),
    ("/usr/bin/openssl", "openssl"),
    ("/usr/bin/bash", "bash"),
    ("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", "libsqlite3"),
    ("/usr/lib/x86_64-linux-gnu/libc.so.6", "libc"),
    ("/usr/bin/git", "git"),
    ("/usr/bin/python3.12", "python3.12"),
]
CALL_NOTE = "outgoing call arguments and return values follow no modelled ABI"
STRUCTURE_NOTE = "control flow not fully structured"


def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def text_range(path):
    out = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True).stdout
    m = re.search(r"\s\.text\s+PROGBITS\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", out)
    start = int(m.group(1), 16)
    return start, start + int(m.group(2), 16)


def write(args):
    rng = random.Random(args.seed)
    lists = {}
    for path, tag in BINARIES:
        lo, hi = text_range(path)
        starts = json.loads(run([args.cli, "functions", path, "--json"]))["functions"]
        addresses = sorted(int(f["address"], 16) for f in starts if lo <= int(f["address"], 16) < hi)
        rng.shuffle(addresses)
        lists[tag] = {"path": path, "population": len(addresses), "addresses": sorted(addresses[: args.per_binary])}
        print(tag, "population", len(addresses), "sampled", len(lists[tag]["addresses"]), flush=True)
    with open(args.out, "w") as handle:
        json.dump({"seed": args.seed, "per_binary": args.per_binary, "binaries": lists}, handle, indent=1)


def measure(args):
    with open(args.list) as handle:
        plan = json.load(handle)
    result = {}
    for tag, entry in plan["binaries"].items():
        wanted = set(entry["addresses"])
        decompiled = json.loads(run([args.cli, "decompile", entry["path"], "--json",
                                     "--max-functions", "1000000"]))
        counts = {"sampled": 0, "found": 0, "Complete": 0, "Partial": 0, "Unsupported": 0,
                  "InvalidIR": 0, "call_note": 0, "structure_note": 0}
        for function in decompiled["functions"]:
            address = int(function["address"], 16)
            if address not in wanted:
                continue
            counts["found"] += 1
            status = function["status"]
            counts[status] = counts.get(status, 0) + 1
            text = function.get("pseudocode") or ""
            counts["call_note"] += int(CALL_NOTE in text)
            counts["structure_note"] += int(STRUCTURE_NOTE in text)
        counts["sampled"] = len(wanted)
        result[tag] = counts
        print(tag, counts, flush=True)
    with open(args.out, "w") as handle:
        json.dump({"cli": args.cli, "result": result}, handle, indent=1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["write", "measure"])
    parser.add_argument("file")
    parser.add_argument("out", nargs="?")
    parser.add_argument("--per-binary", type=int, default=300)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--cli", default="/home/user/donkey/build/release-headless/apps/donkey-cli/donkey-cli")
    args = parser.parse_args()
    if args.mode == "write":
        args.out = args.file
        write(args)
    else:
        args.list = args.file
        args.out = args.out
        measure(args)


if __name__ == "__main__":
    sys.exit(main())
