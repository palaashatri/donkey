#!/usr/bin/env python3
"""Decompile a random sample of .text functions, one process per function, and count outcomes."""
import collections, concurrent.futures, json, os, random, re, subprocess, sys
DONKEY = "/home/user/donkey/build/release-headless/apps/donkey-cli/donkey-cli"
GENERIC = ("subset; locals are not recovered", "signature inferred from", "is assumed")
CALL = "outgoing call arguments and return values follow no modelled ABI"

def text_range(path):
    out = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True).stdout
    m = re.search(r"\s\.text\s+PROGBITS\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", out)
    s = int(m.group(1), 16); return s, s + int(m.group(2), 16)

def one(args):
    path, address = args
    r = subprocess.run(["timeout", "-k", "5", "120", DONKEY, "decompile", path, "--function", hex(address), "--json"],
                       capture_output=True)
    if r.returncode != 0:
        kind = "crash" if r.returncode < 0 or r.returncode >= 128 else "timeout" if r.returncode == 124 else "error"
        return address, kind, [], None
    try:
        f = json.loads(r.stdout)["functions"][0]
    except Exception:
        return address, "bad-json", [], None
    notes = re.findall(r"// note: (.*)", f.get("pseudocode") or "")
    return address, f["status"], notes, f.get("code")

def run(path, tag, n, seed=7):
    lo, hi = text_range(path)
    fs = json.loads(subprocess.run([DONKEY, "functions", path, "--json"], capture_output=True).stdout)["functions"]
    addresses = sorted(int(f["address"], 16) for f in fs if lo <= int(f["address"], 16) < hi)
    random.Random(seed).shuffle(addresses)
    sample = addresses[:n]
    status = collections.Counter(); codes = collections.Counter(); reasons = collections.Counter()
    only_calls = 0; crashes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for address, st, notes, code in pool.map(one, [(path, a) for a in sample]):
            status[st] += 1
            if code: codes[code] += 1
            if st == "crash": crashes.append(hex(address))
            if st == "Partial":
                real = [x for x in notes if not any(g in x for g in GENERIC)]
                for x in set(re.sub(r"0x[0-9a-f]+", "<addr>", y)[:90] for y in real): reasons[x] += 1
                if real and all(CALL in x for x in real): only_calls += 1
    row = {"tag": tag, "text_functions": len(addresses), "sampled": len(sample), "status": dict(status),
           "invalid_codes": dict(codes), "partial_only_because_of_calls": only_calls,
           "partial_reasons": reasons.most_common(8), "crashes": crashes[:8]}
    print(json.dumps(row), flush=True)

if __name__ == "__main__":
    for path, tag in [
        ("/usr/bin/ls", "ls"), ("/usr/bin/bash", "bash"), ("/usr/bin/openssl", "openssl"),
        ("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", "libsqlite3"),
        ("/usr/lib/x86_64-linux-gnu/libc.so.6", "libc"),
        ("/home/user/donkey/build/release-headless/apps/donkey-cli/donkey-cli", "own-x86-64"),
        ("/home/user/donkey/build/cross-a64/apps/donkey-cli/donkey-cli", "own-aarch64"),
    ]:
        run(path, tag, 300)
    print("SAMPLE DONE", flush=True)
