# Donkey audit scripts

Measurement scripts behind `docs/AUDIT.md`. They run the `donkey-cli` binary; use the Release build
(`cmake --build build/release-headless`). Run them with `python3 -I`.

- `audit.py`: function starts found by Donkey and by radare2 (`r2`) scored against symbols or
  `.eh_frame` entries, with time and memory, and a 200-binary robustness sweep.
- `sample.py`: decompiles 300 randomly chosen `.text` functions per binary (fixed seed), one process
  per function, and counts the outcomes and the reasons for Partial. Its population changes when
  the function discovery changes; use `sample_list.py` for comparisons.
- `sample_list.py`: the same-population measurement. `write` draws a fixed list of function starts
  (seed 7, 300 per binary) from one commit; `measure` decompiles every system binary once and counts,
  for the listed addresses only, the status and the notes "no modelled ABI" and "not fully
  structured". Only system binaries are used: their files are the same at every commit.
  `results/` holds the list and the three logs behind the table in `docs/AUDIT.md`.

Example:

    python3 -I tools/audit/sample_list.py write list.json --cli build/release-headless/apps/donkey-cli/donkey-cli
    python3 -I tools/audit/sample_list.py measure list.json out.json --cli build/release-headless/apps/donkey-cli/donkey-cli
