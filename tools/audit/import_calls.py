#!/usr/bin/env python3
"""Import calls in the decompiler output (docs/IDA_GAP_LEDGER.md, "G24-T0 task-level plan").

    python3 -I tools/audit/import_calls.py LIST.json OUT.json [--cli PATH]

For the fixed sample LIST.json (tools/audit/results/list_final.json), runs `decompile --json` once
per binary and counts, over every sampled function:

  - direct calls printed as `sub_<hex>(` whose target is an ELF import stub (inside .plt, .plt.sec
    or .plt.got), and the functions that contain one;
  - the import each stub calls, named by `objdump -d` (`<name@plt>`), an oracle independent of
    Donkey's own stub reader;
  - calls to the known no-return imports below, how many of them the printed code follows with a
    `return`, and how many Partial functions that call one carry the note "the returned register
    is not determined by the definitions that reach the return";
  - calls through a GOT slot (`-fno-plt`), printed as `((void (*)(void))*(u64 *)(0x...))()`;
  - calls printed by a no-return import's name (`abort(`), the form G24-T4 prints, so a `return` after
    one is still counted once stubs are named;
  - calls printed by the name of any import the binary has a stub or a GOT slot for (`puts(`), the
    form G24-T4 prints in place of `sub_<hex>(`.

A sampled address that the CLI does not return is an error: the measurement is refused, not saved
with fewer functions.

Each binary must be the one the list was drawn from (its SHA-256 is checked, as sample_list.py
does), and it is decompiled from a private copy.
"""
import argparse, collections, json, os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sample_list import check_identity, run, sha256_of, stable_copy  # noqa: E402

NO_RETURN = {"abort", "exit", "_exit", "_Exit", "quick_exit", "__stack_chk_fail", "__fortify_fail",
             "__chk_fail", "__assert_fail", "__assert_perror_fail", "err", "errx", "verr", "verrx",
             "longjmp", "siglongjmp", "__longjmp_chk", "pthread_exit", "__cxa_throw",
             "__cxa_rethrow", "_Unwind_Resume", "_ZSt9terminatev", "__libc_fatal"}
# error() does not return only when its status argument is nonzero: counted apart, never as no-return.
SOMETIMES_NO_RETURN = {"error"}
# A call printed by the import's own name, as G24-T4 prints it.
NAMED_NO_RETURN_CALL = re.compile(r"(?<![\w.])(" + "|".join(sorted(NO_RETURN)) + r")\(")
CALL_BY_NAME = re.compile(r"(?<![\w.>])([A-Za-z_]\w*)\(")
RETURN_NOTE = "the returned register is not determined by the definitions that reach the return"
STUB_SECTIONS = (".plt", ".plt.sec", ".plt.got")
GOT_SECTIONS = (".got", ".got.plt")


def sections(path):
    out = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True, check=True).stdout
    found = {}
    for m in re.finditer(r"\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", out):
        start = int(m.group(2), 16)
        found[m.group(1)] = (start, start + int(m.group(3), 16))
    return found


def stub_names(path):
    """objdump's name for each stub: `4750 <abort@plt>:` (no -C, so C++ names stay mangled)."""
    command = ["objdump", "-d"] + [arg for name in STUB_SECTIONS for arg in ("-j", name)] + [path]
    out = subprocess.run(command, capture_output=True, text=True).stdout
    return {int(m.group(1), 16): m.group(2).split("@")[0]
            for m in re.finditer(r"^([0-9a-f]+) <([^>]+)@plt>:$", out, re.M)}


def got_slot_names(path):
    out = subprocess.run(["readelf", "-rW", path], capture_output=True, text=True, check=True).stdout
    slots = {}
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 5 and ("GLOB_DAT" in fields[2] or "JUMP_SLO" in fields[2]):
            slots[int(fields[0], 16)] = fields[4].split("@")[0]
    return slots


def is_signature(line):
    """`type name(params) {` at column 0: the function signature, not an inferred struct."""
    text = line.strip()
    return (line == line.lstrip() and not text.startswith("struct ") and "(" in text
            and text.endswith("{"))


def body_lines(pseudocode):
    """The statement lines after the function signature, without comment lines. Everything up to
    and including the signature is dropped: the signature itself, whatever the function is called
    (`u64 sub_4d7f(void) {` or a named one such as `void siglongjmp(u64 a0) {`), and any inferred
    `struct` the printer puts before it (src/ir/ir.cpp), so neither is ever counted as a call.
    Pseudocode with text but no signature is an error: the measurement is refused.

    >>> body_lines("// note: x\\nu64 sub_10(void) {\\n  abort();\\n  return 0;\\n}")
    ['abort();', 'return 0;', '}']
    >>> body_lines("// note: struct a0_fields inferred from accesses through a0\\n"
    ...            "struct a0_fields {\\n  u64 f_0;  // +0x0\\n  u32 f_8;  // +0x8\\n};\\n"
    ...            "u64 exit(struct a0_fields *a0) {\\n  return a0->f_0;\\n}")
    ['return a0->f_0;', '}']
    >>> body_lines("void siglongjmp(u64 a0) {\\n  abort();\\n}")
    ['abort();', '}']
    >>> body_lines("")
    []
    """
    lines = []
    header_seen = False
    preamble = False
    for line in pseudocode.splitlines():
        text = line.strip()
        if not text or text.startswith("//"):
            continue
        if not header_seen:
            header_seen = is_signature(line)
            preamble = preamble or not header_seen
            continue
        lines.append(text)
    if preamble and not header_seen:
        sys.exit("import_calls.py: a function's pseudocode has no signature line; "
                 "the measurement is refused")
    return lines


def inside(address, ranges):
    return any(start <= address < end for start, end in ranges)


def measure(args):
    with open(args.list) as handle:
        plan = json.load(handle)
    for tag, entry in plan["binaries"].items():
        check_identity(entry["path"], sha256_of(entry["path"]), entry["sha256"])
    counts = collections.Counter()
    sites_by_name = collections.Counter()
    functions_by_name = collections.Counter()
    no_return_sites = collections.Counter()
    no_return_functions = collections.Counter()
    got_names = collections.Counter()
    for tag, entry in plan["binaries"].items():
        wanted = set(entry["addresses"])
        with stable_copy(entry["path"]) as (copy, digest):
            check_identity(entry["path"], digest, entry["sha256"])
            ranges = sections(copy)
            stubs = [ranges[name] for name in STUB_SECTIONS if name in ranges]
            gots = [ranges[name] for name in GOT_SECTIONS if name in ranges]
            names = stub_names(copy)
            slots = got_slot_names(copy)
            import_names = set(names.values()) | set(slots.values())
            decompiled = json.loads(run([args.cli, "decompile", copy, "--json",
                                         "--max-functions", "1000000"]))
        returned = {int(function["address"], 16) for function in decompiled["functions"]}
        missing = sorted(wanted - returned)
        if missing:
            sys.exit(f"import_calls.py: {tag}: {len(missing)} sampled functions were not returned, "
                     f"the first at {hex(missing[0])}; the measurement is refused")
        for function in decompiled["functions"]:
            if int(function["address"], 16) not in wanted:
                continue
            counts["functions"] += 1
            pseudocode = function.get("pseudocode") or ""
            lines = body_lines(pseudocode)
            called = set()
            no_return_called = set()
            for index, line in enumerate(lines):
                for m in re.finditer(r"\bsub_([0-9a-f]+)\(", line):
                    target = int(m.group(1), 16)
                    if not inside(target, stubs):
                        continue
                    counts["stub_call_sites"] += 1
                    name = names.get(target)
                    if name is None:
                        counts["stub_call_sites_without_objdump_name"] += 1
                        continue
                    sites_by_name[name] += 1
                    called.add(name)
                    if name in NO_RETURN:
                        no_return_sites[name] += 1
                        no_return_called.add(name)
                        following = lines[index + 1] if index + 1 < len(lines) else ""
                        if following.startswith("return"):
                            counts["no_return_sites_followed_by_return"] += 1
                    elif name in SOMETIMES_NO_RETURN:
                        counts["sometimes_no_return_sites"] += 1
                for m in NAMED_NO_RETURN_CALL.finditer(line):
                    counts["named_no_return_call_sites"] += 1
                    no_return_sites[m.group(1)] += 1
                    no_return_called.add(m.group(1))
                    following = lines[index + 1] if index + 1 < len(lines) else ""
                    if following.startswith("return"):
                        counts["no_return_sites_followed_by_return"] += 1
                for m in CALL_BY_NAME.finditer(line):
                    if m.group(1) in import_names:
                        counts["import_call_sites_printed_by_name"] += 1
                        called.add(m.group(1))
                for m in re.finditer(r"\*\(u64 \*\)\((0x[0-9a-f]+)\)\)\(", line):
                    slot = int(m.group(1), 16)
                    if inside(slot, gots):
                        counts["got_call_sites"] += 1
                        got_names[slots.get(slot, "<no relocation>")] += 1
            if called:
                counts["functions_with_a_stub_call"] += 1
                functions_by_name.update(called)
            if no_return_called:
                counts["functions_with_a_no_return_call"] += 1
                no_return_functions.update(no_return_called)
            partial_with_note = function["status"] == "Partial" and RETURN_NOTE in pseudocode
            counts["partial_with_the_return_note"] += int(partial_with_note)
            counts["partial_with_the_return_note_and_a_no_return_call"] += int(
                partial_with_note and bool(no_return_called))
            counts["complete"] += int(function["status"] == "Complete")
        print(tag, "measured", flush=True)
    result = {
        "counts": dict(counts),
        "stub_call_sites_by_import": sites_by_name.most_common(),
        "functions_by_import": functions_by_name.most_common(),
        "no_return_call_sites": dict(no_return_sites),
        "functions_by_no_return_import": dict(no_return_functions),
        "got_call_sites_by_import": got_names.most_common(),
    }
    with open(args.out, "w") as handle:
        json.dump(result, handle, indent=1)
    print(json.dumps(result["counts"], indent=1))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("list")
    parser.add_argument("out")
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    parser.add_argument("--cli", default=os.path.join(repo, "build", "release-headless", "apps",
                                                      "donkey-cli", "donkey-cli"))
    measure(parser.parse_args())


if __name__ == "__main__":
    main()
