#!/usr/bin/env python3
"""Scale benchmark for donkey-cli analyze (G16-T1).

Two kinds of input. With no --binary, it generates synthetic C programs of several sizes (fixed
seed, so the inputs are the same on every run) and compiles them with the C compiler. With --binary,
it measures real binaries that already exist on the machine, which are not built or modified here.
Either way it measures `donkey-cli analyze` on each input: wall-clock time, the peak resident memory
of the child process, and the status and counts the analysis reported. Results are printed as a table
and written as JSON.

Usage:
  python3 tools/bench/scale_benchmark.py --cli build/headless-linux/apps/donkey-cli/donkey-cli \
      --work /tmp/donkey-bench --sizes 2000 10000 40000 --json results.json

  python3 tools/bench/scale_benchmark.py --cli build/release/apps/donkey-cli/donkey-cli \
      --work /tmp/donkey-bench --binary /usr/lib/llvm-18/lib/libLLVM.so.1 --max-instructions 10000000 \
      --json llvm-results.json

The peak memory is ru_maxrss of the child, so it counts the whole process. Run each size once
per machine; numbers from one run are not a distribution. Record the machine with the results.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path


def generate(functions: int, path: Path) -> None:
    """A program of `functions` small functions in three shapes: a loop, a recursive call, and
    straight-line arithmetic. The seed is fixed so every run compiles the same source."""
    rng = random.Random(1)
    lines = ["#include <stdio.h>", "volatile long sink;"]
    for i in range(functions):
        a = rng.randrange(1, 100)
        if i % 7 == 0:
            lines.append(f"int f{i}(int x) {{ int s = 0; for (int i = 0; i < x; i++) s += i * {a}; return s; }}")
        elif i % 7 == 1:
            lines.append(f"int f{i}(int x) {{ if (x > {a}) return f{max(0, i - 1)}(x - 1) + {a}; return x * {a}; }}")
        else:
            lines.append(f"int f{i}(int x) {{ sink += x ^ {a}; return (x << 3) + {a} + (x >> 2); }}")
    lines.append("int main(int argc, char** argv) { int s = 0;")
    for i in range(0, functions, 97):
        lines.append(f"  s += f{i}(argc);")
    lines.append('  printf("%d\\n", s); return 0; }')
    path.write_text("\n".join(lines) + "\n")


def machine() -> dict:
    model = "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    memory_kb = 0
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemTotal:"):
                memory_kb = int(line.split()[1])
                break
    return {
        "platform": platform.platform(),
        "cpu": model,
        "cpus": os.cpu_count(),
        "memory_mb": memory_kb // 1024,
    }


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def measure(cli: str, binary: Path, scratch: Path, max_instructions: int) -> dict:
    """Runs `donkey-cli analyze` and reads its own resource usage. RUSAGE_CHILDREN would report the
    largest child seen so far, which here can be the C compiler, so the child is waited for by pid."""
    output = scratch / "analyze.out"
    start = time.monotonic()
    with output.open("w") as sink:
        process = subprocess.Popen([cli, "analyze", str(binary), "--max-instructions", str(max_instructions)],
                                   stdout=sink, stderr=subprocess.STDOUT)
        _, status, usage = os.wait4(process.pid, 0)
    wall = time.monotonic() - start
    summary = {}
    for line in output.read_text().splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            summary[key.strip()] = value.strip()
    return {
        "exit": os.waitstatus_to_exitcode(status),
        "wall_seconds": round(wall, 3),
        "peak_rss_mb": round(usage.ru_maxrss / 1024, 1),
        "status": summary.get("Status"),
        "instructions": summary.get("Instructions"),
        "functions": summary.get("Functions"),
        "blocks": summary.get("Blocks"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", required=True, help="path to donkey-cli")
    parser.add_argument("--work", required=True, help="directory for the generated sources and binaries")
    parser.add_argument("--cc", default=os.environ.get("CC", "gcc"), help="C compiler (default: $CC or gcc)")
    parser.add_argument("--sizes", type=int, nargs="+", default=None,
                        help="function counts of the synthetic programs (default 2000 10000 40000 when no "
                             "--binary is given)")
    parser.add_argument("--binary", action="append", default=[],
                        help="measure this existing binary instead of the synthetic programs (repeatable)")
    parser.add_argument("--max-instructions", type=int, default=4_000_000,
                        help="instruction cap for analyze; a run that hits it is Partial, not Complete")
    parser.add_argument("--json", help="write the results to this file")
    args = parser.parse_args()

    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    results = []
    sizes = args.sizes if args.sizes is not None else ([] if args.binary else [2000, 10000, 40000])
    for path in args.binary:
        binary = Path(path)
        row = {
            "binary": str(binary),
            "binary_bytes": binary.stat().st_size,
            "sha256": sha256_of(binary),
        }
        row.update(measure(args.cli, binary, work, args.max_instructions))
        results.append(row)
        print(f"{binary.name:<28} {row['binary_bytes']:>12} bytes  {row['wall_seconds']:>8.2f} s  "
              f"{row['peak_rss_mb']:>8.1f} MB  {row['status']}  exit {row['exit']}", flush=True)
    for functions in sizes:
        source = work / f"synthetic-{functions}.c"
        binary = work / f"synthetic-{functions}"
        generate(functions, source)
        compile_start = time.monotonic()
        subprocess.run([args.cc, "-O2", "-o", str(binary), str(source)], check=True)
        compile_seconds = time.monotonic() - compile_start
        row = {
            "functions_in_source": functions,
            "binary_bytes": binary.stat().st_size,
            "compile_seconds": round(compile_seconds, 2),
        }
        row.update(measure(args.cli, binary, work, args.max_instructions))
        results.append(row)
        print(f"{functions:>7} functions  {row['binary_bytes']:>10} bytes  "
              f"{row['wall_seconds']:>8.2f} s  {row['peak_rss_mb']:>8.1f} MB  exit {row['exit']}",
              flush=True)

    report = {"machine": machine(), "compiler": args.cc if sizes else None,
              "max_instructions": args.max_instructions, "results": results}
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n")
    shutil.rmtree(work / "__pycache__", ignore_errors=True)
    return 0 if all(row["exit"] == 0 for row in results) else 1


if __name__ == "__main__":
    sys.exit(main())
