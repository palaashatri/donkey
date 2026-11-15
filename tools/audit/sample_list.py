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
      "control flow not fully structured" (labelled note), and the control-flow fields of the
      structure object (G04-T5): the class (structured, goto_structured, other), the number of gotos,
      the candidate structures the control-flow check refused, and whether the printed code is labelled.
      The same list measured on two commits gives the same functions in both.

Only system binaries are used: their files are identical at every commit, so the population is
the same by construction. A commit's own donkey-cli is a different file at each commit.
"""
import argparse, contextlib, hashlib, json, os, random, re, shutil, subprocess, sys, tempfile

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
# The whole line the printer writes in front of a labelled function (src/ir/ir.cpp).
STRUCTURE_NOTE_LINE = "// note: control flow not fully structured; showing labeled blocks"
GOTO_NOTE = " goto(s) where control flow has no structured form"
# Structure classes of the command-line JSON. Since G04-T5, "other" is the labelled form and the two
# structured classes are not. Before it, "irreducible" and "reducible_rejected" named functions that
# were printed labelled, with the note, and "other" named functions with no structure question.
LABELLED_CLASSES = {"other"}
STRUCTURED_CLASSES = {"structured", "goto_structured"}


def is_labelled(structure, has_note):
    """Whether a function was printed as labelled blocks: by its class when the class decides, by
    the printer's note line for the classes of older tools ("irreducible", "reducible_rejected")
    and for output with no class."""
    cls = structure.get("class")
    if cls in LABELLED_CLASSES:
        return True
    if cls in STRUCTURED_CLASSES:
        return False
    return has_note


def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def sha256_of(path):
    """The binary's content hash: a list's addresses are only meaningful for these exact bytes."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextlib.contextmanager
def stable_copy(path):
    """A private copy of the binary and its hash. Reading, sampling and decompiling the copy means
    the hash names exactly the bytes measured, even if a package update replaces `path` meanwhile."""
    with tempfile.TemporaryDirectory(prefix="donkey-sample-") as directory:
        copy = os.path.join(directory, os.path.basename(path))
        shutil.copyfile(path, copy)
        yield copy, sha256_of(copy)


def text_range(path):
    out = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True).stdout
    m = re.search(r"\s\.text\s+PROGBITS\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", out)
    start = int(m.group(1), 16)
    return start, start + int(m.group(2), 16)


def write(args):
    rng = random.Random(args.seed)
    lists = {}
    for path, tag in BINARIES:
        with stable_copy(path) as (copy, digest):
            lo, hi = text_range(copy)
            starts = json.loads(run([args.cli, "functions", copy, "--json"]))["functions"]
        addresses = sorted(int(f["address"], 16) for f in starts if lo <= int(f["address"], 16) < hi)
        rng.shuffle(addresses)
        lists[tag] = {"path": path, "sha256": digest, "population": len(addresses),
                      "addresses": sorted(addresses[: args.per_binary])}
        print(tag, "population", len(addresses), "sampled", len(lists[tag]["addresses"]), flush=True)
    with open(args.out, "w") as handle:
        json.dump({"seed": args.seed, "per_binary": args.per_binary, "binaries": lists}, handle, indent=1)


def check_identity(path, actual, expected):
    if actual != expected:
        sys.exit(f"sample_list.py: {path} is not the binary the list was drawn from "
                 f"(sha256 {actual}, list {expected})")


def measure(args):
    with open(args.list) as handle:
        plan = json.load(handle)
    result = {}
    # A package update can replace a binary at the same path: the sampled addresses would then name
    # other code. Every binary must be the one the list was drawn from: each is checked before any
    # is measured, and each is measured from a copy whose hash is checked again.
    for tag, entry in plan["binaries"].items():
        if entry.get("sha256") is None:
            sys.exit(f"sample_list.py: the list has no sha256 for {tag}; it cannot be measured safely")
        check_identity(entry["path"], sha256_of(entry["path"]), entry["sha256"])
    for tag, entry in plan["binaries"].items():
        wanted = set(entry["addresses"])
        with stable_copy(entry["path"]) as (copy, digest):
            check_identity(entry["path"], digest, entry["sha256"])
            decompiled = json.loads(run([args.cli, "decompile", copy, "--json",
                                         "--max-functions", "1000000"]))
        classes = {}
        reasons = {}
        counts = {"sampled": 0, "found": 0, "Complete": 0, "Partial": 0, "Unsupported": 0,
                  "InvalidIR": 0, "call_note": 0, "structure_note": 0, "labelled": 0,
                  "goto_functions": 0, "gotos_total": 0, "gotos_max": 0,
                  "oracle_rejected_candidates": 0, "functions_with_a_rejected_candidate": 0}
        for function in decompiled["functions"]:
            address = int(function["address"], 16)
            if address not in wanted:
                continue
            counts["found"] += 1
            status = function["status"]
            counts[status] = counts.get(status, 0) + 1
            text = function.get("pseudocode") or ""
            counts["call_note"] += int(CALL_NOTE in text)
            # The note is a whole line of its own; a string literal that quotes it is not the note.
            has_note = any(line.strip() == STRUCTURE_NOTE_LINE for line in text.splitlines())
            counts["structure_note"] += int(has_note)
            structure = function.get("structure") or {}
            cls = structure.get("class", "none")
            classes[cls] = classes.get(cls, 0) + 1
            gotos = int(structure.get("gotos", 0))
            counts["labelled"] += int(is_labelled(structure, has_note))
            if gotos > 0:
                counts["goto_functions"] += 1
                counts["gotos_total"] += gotos
                counts["gotos_max"] = max(counts["gotos_max"], gotos)
            rejected = int(structure.get("oracle_rejections", 0))
            counts["oracle_rejected_candidates"] += rejected
            counts["functions_with_a_rejected_candidate"] += int(rejected > 0)
            # The printed code is checked before it is shown, so a labelled function is the only
            # printed result that failed the check (the labelled form is not checked).
            if cls in ("goto_structured", "other") and structure.get("reason"):
                reasons[structure["reason"]] = reasons.get(structure["reason"], 0) + 1
        counts["sampled"] = len(wanted)
        counts["structure_classes"] = classes
        counts["rejection_reasons"] = reasons
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
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    parser.add_argument("--cli", default=os.path.join(repo, "build", "release-headless", "apps",
                                                      "donkey-cli", "donkey-cli"))
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
