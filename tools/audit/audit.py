#!/usr/bin/env python3
"""Measured audit of donkey-cli on real binaries.

For each binary: function starts found by Donkey and by radare2, scored against ground truth
(symbols of the unstripped file, and .eh_frame FDE starts), with wall time and peak memory.
For a subset: decompiler status counts and the reasons functions are Partial.
A robustness sweep runs Donkey over many system binaries and classifies how each run ends.
"""
import collections
import json
import os
import re
import subprocess
import sys
import time

DONKEY = "/home/user/donkey/build/release-headless/apps/donkey-cli/donkey-cli"
OUT = os.path.dirname(os.path.abspath(__file__))


def timed(cmd, timeout, stdout_path):
    """Run cmd with a wall-clock limit. Returns (exit, seconds, peak_rss_mib)."""
    start = time.time()
    with open(stdout_path, "wb") as out, open(os.devnull, "wb") as err:
        proc = subprocess.Popen(["timeout", "-k", "5", str(timeout)] + cmd, stdout=out, stderr=err)
        _, status, usage = os.wait4(proc.pid, 0)
    wall = time.time() - start
    code = os.waitstatus_to_exitcode(status)
    return code, wall, usage.ru_maxrss / 1024.0


def text_range(path):
    out = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = re.search(r"\s\.text\s+PROGBITS\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", line)
        if m:
            start = int(m.group(1), 16)
            return start, start + int(m.group(2), 16)
    return None


def symbol_starts(path, rng):
    out = subprocess.run(["nm", "--defined-only", path], capture_output=True, text=True).stdout
    starts, cold = set(), set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1] not in "TtWw":
            continue
        address = int(parts[0], 16)
        if not (rng[0] <= address < rng[1]):
            continue
        (cold if ".cold" in parts[2] else starts).add(address)
    return starts, cold


def fde_starts(path, rng):
    out = subprocess.run(["readelf", "--debug-dump=frames", path], capture_output=True, text=True).stdout
    starts = set()
    for m in re.finditer(r" FDE .*pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        address = int(m.group(1), 16)
        if rng[0] <= address < rng[1]:
            starts.add(address)
    return starts


def donkey_starts(path, tag):
    out = os.path.join(OUT, f"{tag}.functions.json")
    code, wall, rss = timed([DONKEY, "functions", path, "--json"], 900, out)
    starts, estimated = set(), 0
    if code == 0:
        try:
            data = json.load(open(out))
            for f in data.get("functions", []):
                starts.add(int(f["address"], 16))
                estimated += 1 if f.get("estimated") else 0
        except (ValueError, KeyError):
            code = -1
    os.remove(out)
    return {"exit": code, "seconds": round(wall, 2), "rss_mib": round(rss, 1), "estimated": estimated}, starts


def r2_starts(path, tag, level):
    out = os.path.join(OUT, f"{tag}.r2.txt")
    code, wall, rss = timed(["r2", "-q", "-e", "scr.color=0", "-c", f"{level}; aflq", path], 900, out)
    starts = set()
    for line in open(out, errors="replace"):
        line = line.strip()
        if re.fullmatch(r"0x[0-9a-f]+", line):
            starts.add(int(line, 16))
    os.remove(out)
    return {"exit": code, "seconds": round(wall, 2), "rss_mib": round(rss, 1), "level": level}, starts


def score(found, truth, rng, ignore=frozenset()):
    found = {a for a in found if rng[0] <= a < rng[1]} - ignore
    truth = truth - ignore
    hit = len(found & truth)
    return {
        "found": len(found),
        "truth": len(truth),
        "hit": hit,
        "recall": round(100.0 * hit / len(truth), 1) if truth else None,
        "precision": round(100.0 * hit / len(found), 1) if found else None,
    }


def decompile_stats(path, tag):
    """Stream the decompile JSON; count statuses and notes without holding it in memory."""
    start = time.time()
    proc = subprocess.Popen(["timeout", "-k", "5", "1800", DONKEY, "decompile", path, "--json"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    statuses = collections.Counter()
    notes = collections.Counter()
    only_call_partial = 0
    with_call_note = 0
    head = re.compile(rb'^\s*\{"address": "0x[0-9a-f]+", "name": .*?"status": "([A-Za-z]+)"')
    note = re.compile(rb"// note: (.*?)\\n")
    generic = (b"subset; locals are not recovered", b"signature inferred from", b"is assumed")
    call_note = b"outgoing call arguments and return values follow no modelled ABI"
    for line in proc.stdout:
        m = head.match(line)
        if not m:
            continue
        status = m.group(1).decode()
        statuses[status] += 1
        found = note.findall(line)
        for n in found:
            text = re.sub(rb"0x[0-9a-f]+", b"<addr>", n).decode(errors="replace")[:110]
            notes[text] += 1
        if status == "Partial":
            reasons = [n for n in found if not any(g in n for g in generic)]
            if any(call_note in n for n in found):
                with_call_note += 1
                if all(call_note in n for n in reasons):
                    only_call_partial += 1
    _, status, usage = os.wait4(proc.pid, 0)
    return {
        "exit": os.waitstatus_to_exitcode(status),
        "seconds": round(time.time() - start, 1),
        "rss_mib": round(usage.ru_maxrss / 1024.0, 1),
        "statuses": dict(statuses),
        "partial_with_call_note": with_call_note,
        "partial_only_because_of_calls": only_call_partial,
        "top_notes": notes.most_common(12),
    }


def analyse(path, tag, r2_level="aaa", truth="fde", decompile=False):
    row = {"tag": tag, "path": path, "bytes": os.path.getsize(path)}
    rng = text_range(path)
    row["text_bytes"] = rng[1] - rng[0]
    fde = fde_starts(path, rng)
    sym, cold = symbol_starts(path, rng)
    truth_set = sym if truth == "symbols" else fde
    row["truth_kind"] = truth
    row["symbols"] = len(sym)
    row["fde"] = len(fde)
    info, found = donkey_starts(path, tag)
    row["donkey"] = info
    row["donkey_score"] = score(found, truth_set, rng, cold)
    if r2_level:
        info, found = r2_starts(path, tag, r2_level)
        row["r2"] = info
        row["r2_score"] = score(found, truth_set, rng, cold)
    if decompile:
        row["decompile"] = decompile_stats(path, tag)
    print(json.dumps(row), flush=True)
    return row


def sweep(limit):
    names = sorted(os.listdir("/usr/bin"))
    picked = []
    for name in names:
        p = os.path.join("/usr/bin", name)
        try:
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            size = os.path.getsize(p)
            if not (20_000 <= size <= 12_000_000):
                continue
            with open(p, "rb") as f:
                if f.read(4) != b"\x7fELF":
                    continue
        except OSError:
            continue
        picked.append(p)
        if len(picked) >= limit:
            break
    result = collections.Counter()
    worst = []
    total = 0.0
    scratch = os.path.join(OUT, "sweep.out")
    for p in picked:
        code, wall, rss = timed([DONKEY, "functions", p, "--json"], 120, scratch)
        total += wall
        kind = "ok" if code == 0 else "timeout" if code == 124 else "crash" if code < 0 or code >= 128 else "refused"
        result[kind] += 1
        worst.append((round(wall, 1), round(rss), kind, p))
    os.remove(scratch)
    worst.sort(reverse=True)
    row = {"tag": "sweep", "files": len(picked), "result": dict(result), "seconds_total": round(total, 1),
           "slowest": worst[:5], "not_ok": [w for w in worst if w[2] != "ok"][:15]}
    print(json.dumps(row), flush=True)
    return row


if __name__ == "__main__":
    rows = []
    own = "/home/user/donkey/build/release-headless/apps/donkey-cli/donkey-cli"
    stripped = os.path.join(OUT, "donkey-cli.stripped")
    subprocess.run(["strip", "-o", stripped, own], check=True)
    # The same program with and without symbols: symbols are the ground truth for both.
    rows.append(analyse(own, "own-symbols", truth="symbols", decompile=True))
    r = analyse(stripped, "own-stripped", truth="fde", decompile=False)
    # Score the stripped run against the unstripped file's symbols too.
    rng = text_range(own)
    sym, cold = symbol_starts(own, rng)
    info, found = donkey_starts(stripped, "own-stripped-sym")
    r["donkey_score_vs_symbols"] = score(found, sym, rng, cold)
    info2, found2 = r2_starts(stripped, "own-stripped-sym", "aaa")
    r["r2_score_vs_symbols"] = score(found2, sym, rng, cold)
    print(json.dumps({"tag": "own-stripped-vs-symbols", "donkey": r["donkey_score_vs_symbols"],
                      "r2": r["r2_score_vs_symbols"]}), flush=True)
    rows.append(r)
    for path, tag, dec in [
        ("/usr/bin/ls", "ls", True),
        ("/usr/bin/openssl", "openssl", True),
        ("/usr/bin/bash", "bash", True),
        ("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", "libsqlite3", True),
        ("/usr/lib/x86_64-linux-gnu/libc.so.6", "libc", False),
        ("/usr/bin/git", "git", False),
        ("/usr/bin/python3.12", "python3.12", False),
    ]:
        rows.append(analyse(path, tag, decompile=dec))
    a64 = "/home/user/donkey/build/cross-a64/apps/donkey-cli/donkey-cli"
    if os.path.exists(a64):
        rows.append(analyse(a64, "own-aarch64", truth="symbols", decompile=True))
    rows.append(sweep(200))
    json.dump(rows, open(os.path.join(OUT, "results.json"), "w"), indent=1)
    print("AUDIT DONE", flush=True)
