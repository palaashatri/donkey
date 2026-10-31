#!/usr/bin/env python3
"""Convert the BMP screenshots CI captured (one artifact directory per
platform, named screenshots-<platform>) into PNGs under
docs/images/screenshots/<platform>/ and write an index page.

    python3 tools/screenshots_to_png.py <artifacts-dir> <out-dir> <commit> <run-id>
"""
import pathlib
import sys

from PIL import Image

CAPTIONS = {
    "01-workspace": "Workspace on the demo program: sections, functions, disassembly, "
                    "pseudocode, hex view, overview",
    "02-switch-decompiled": "A switch compiled to a jump table, recovered from the bounds "
                            "check and the table bytes",
    "03-loop-and-dwarf": "A loop over a struct array, with the DWARF prototype shown beside "
                         "the pseudocode",
    "04-component-gallery": "Shared UI components and the 1,000,000-row virtualised table",
    "05-debugger-breakpoint": "The native debugger stopped at a breakpoint (Linux and Windows "
                              "only)",
}


def main() -> int:
    artifacts, out, commit, run = (pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]),
                                   sys.argv[3], sys.argv[4])
    out.mkdir(parents=True, exist_ok=True)
    platforms = []
    for directory in sorted(artifacts.glob("screenshots-*")):
        platform = directory.name[len("screenshots-"):]
        target = out / platform
        target.mkdir(parents=True, exist_ok=True)
        names = []
        for bmp in sorted(directory.rglob("*.bmp")):
            Image.open(bmp).convert("RGB").save(target / (bmp.stem + ".png"), optimize=True)
            names.append(bmp.stem)
        platforms.append((platform, names))
    lines = [
        "# Screenshots",
        "",
        (f"Captured by `.github/workflows/package.yml` (run {run}, commit {commit[:12]}) from the"
         if run != "local" else
         f"Captured locally under Xvfb (commit {commit[:12]}) from the"),
        "`ui.screenshots` test: `tests/ui/screenshots.donkeyui` drives the real application",
        "on `tests/fixtures/demo/demo.c`, built on each platform with its own compiler, using",
        "the software renderer. Nothing here is edited by hand.",
        "",
    ]
    for platform, names in platforms:
        lines += [f"## {platform}", ""]
        for name in names:
            caption = CAPTIONS.get(name, name)
            lines += [f"![{caption}]({platform}/{name}.png)", "", f"*{caption}*", ""]
    (out / "README.md").write_text("\n".join(lines))
    print("\n".join(f"{p}: {len(n)} screenshots" for p, n in platforms))
    return 0 if platforms else 1


if __name__ == "__main__":
    sys.exit(main())
