# Screenshots

Captured by `.github/workflows/package.yml` (run 41237516035, commit be1bb971330b) from the
`ui.screenshots` test: `tests/ui/screenshots.donkeyui` drives the real application
on `tests/fixtures/demo/demo.c`, built on each platform with its own compiler, using
the software renderer. The images are not edited; captions come from
`tools/screenshots_to_png.py`.

## freebsd-arm64

![Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview](freebsd-arm64/01-workspace.png)

*Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview*

![category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks](freebsd-arm64/02-switch-decompiled.png)

*category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks*

![stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled](freebsd-arm64/03-loop-and-dwarf.png)

*stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled*

![Shared UI components and the 1,000,000-row virtualised table](freebsd-arm64/04-component-gallery.png)

*Shared UI components and the 1,000,000-row virtualised table*

## freebsd-x86_64

![Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview](freebsd-x86_64/01-workspace.png)

*Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview*

![category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks](freebsd-x86_64/02-switch-decompiled.png)

*category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks*

![stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled](freebsd-x86_64/03-loop-and-dwarf.png)

*stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled*

![Shared UI components and the 1,000,000-row virtualised table](freebsd-x86_64/04-component-gallery.png)

*Shared UI components and the 1,000,000-row virtualised table*

## linux-arm64

![Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview](linux-arm64/01-workspace.png)

*Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview*

![category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks](linux-arm64/02-switch-decompiled.png)

*category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks*

![stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled](linux-arm64/03-loop-and-dwarf.png)

*stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled*

![Shared UI components and the 1,000,000-row virtualised table](linux-arm64/04-component-gallery.png)

*Shared UI components and the 1,000,000-row virtualised table*

![The native debugger stopped at a breakpoint (Linux and Windows only)](linux-arm64/05-debugger-breakpoint.png)

*The native debugger stopped at a breakpoint (Linux and Windows only)*

## linux-x86_64

![Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview](linux-x86_64/01-workspace.png)

*Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview*

![category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks](linux-x86_64/02-switch-decompiled.png)

*category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks*

![stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled](linux-x86_64/03-loop-and-dwarf.png)

*stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled*

![Shared UI components and the 1,000,000-row virtualised table](linux-x86_64/04-component-gallery.png)

*Shared UI components and the 1,000,000-row virtualised table*

![The native debugger stopped at a breakpoint (Linux and Windows only)](linux-x86_64/05-debugger-breakpoint.png)

*The native debugger stopped at a breakpoint (Linux and Windows only)*

## macos-arm64

![Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview](macos-arm64/01-workspace.png)

*Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview*

![category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks](macos-arm64/02-switch-decompiled.png)

*category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks*

![stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled](macos-arm64/03-loop-and-dwarf.png)

*stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled*

![Shared UI components and the 1,000,000-row virtualised table](macos-arm64/04-component-gallery.png)

*Shared UI components and the 1,000,000-row virtualised table*

## windows-arm64

![Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview](windows-arm64/01-workspace.png)

*Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview*

![category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks](windows-arm64/02-switch-decompiled.png)

*category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks*

![stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled](windows-arm64/03-loop-and-dwarf.png)

*stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled*

![Shared UI components and the 1,000,000-row virtualised table](windows-arm64/04-component-gallery.png)

*Shared UI components and the 1,000,000-row virtualised table*

## windows-x86_64

![Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview](windows-x86_64/01-workspace.png)

*Workspace on the demo program: sections, functions, disassembly, pseudocode, hex view, overview*

![category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks](windows-x86_64/02-switch-decompiled.png)

*category_name, a switch in the source. Compilers emit it differently: a jump table (x86) or a bounds check and a lookup table (Apple Clang). Where the control flow is not structured, the exact pseudocode is shown as labelled blocks*

![stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled](windows-x86_64/03-loop-and-dwarf.png)

*stock_value, a loop over a struct array. Where the binary carries DWARF (not macOS, which keeps it in a .dSYM bundle Donkey does not read), its prototype is shown above the pseudocode. Partial where an instruction or flag is not modelled*

![Shared UI components and the 1,000,000-row virtualised table](windows-x86_64/04-component-gallery.png)

*Shared UI components and the 1,000,000-row virtualised table*

![The native debugger stopped at a breakpoint (Linux and Windows only)](windows-x86_64/05-debugger-breakpoint.png)

*The native debugger stopped at a breakpoint (Linux and Windows only)*
