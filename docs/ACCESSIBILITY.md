# Accessibility design (G19, first step)

Status: **design only**. Nothing in this document is implemented, and no screen reader is supported
today. The ledger's G19 row stays BLOCKED until the owner decides the open questions in section 5.
Facts about other projects below are as of this writing and were not re-checked against their
current releases; treat them as starting points to verify, not as settled.

## 1. The problem

The desktop shell is built with Dear ImGui, and Dear ImGui draws its own widgets into a render
target. It does not build an accessibility tree, so a platform screen reader sees one opaque
surface. The same holds for the keyboard focus model: the shell has keyboard navigation through the
scripted UI tests (`docs/UI_TESTING.md`), but a user of assistive technology cannot discover what
has focus, what a control is, or what its value is.

The rules that bind this work (AGENTS.md) are: C++20 for Donkey-owned code, Objective-C++ only for
minimal macOS shims, no Rust in Donkey code, and shared components in `src/ui/components`, so the
semantics live in one place.

## 2. What an accessibility bridge needs

A bridge has two parts, and the first one is independent of any platform:

1. **A semantic model** built from the shared components. Each component reports a role (button,
   text field, list, tree item, tab, dialog, menu item and so on), an accessible name, a value where
   it has one, its state (focused, selected, expanded, disabled, checked), and its bounds in window
   coordinates. Features do not write this themselves; they use the shared components, as the rules
   already require. The model is a snapshot per frame, produced on the render thread and read by the
   bridge without blocking it.
2. **A platform adapter** that publishes the model to the operating system:
   - **Windows:** UI Automation (`IRawElementProviderSimple` and its relatives), with the provider
     tree built from the snapshot.
   - **Linux:** AT-SPI 2 over D-Bus, with objects for each snapshot element.
   - **macOS:** `NSAccessibility` protocols on the views the shell owns, through a minimal
     Objective-C++ shim (the AGENTS.md exception).

   Each adapter is a separate target, so a platform that has none builds without it, and reports
   accessibility as unsupported rather than pretending to have it.

Keyboard focus is part of the same model: the snapshot names the focused element, and moving focus
through the bridge uses the shell's own focus handling, so a screen reader and a keyboard user see
the same thing.

## 3. Options for the bridge

| Option | Fits the rules | Cost and risk |
|---|---|---|
| A. Per-platform adapters over a Donkey semantic model (section 2) | Yes: C++, with an Objective-C++ shim on macOS only | Three adapters to write and to test on real assistive technology. Each one needs a platform machine to verify |
| B. AccessKit (a Rust library with C bindings, MIT or Apache-2.0) | No, as things stand: the rules forbid Rust for Donkey code. Using it would mean a waiver, or vendoring its C interface around a Rust build | Would cover the three platforms with one library. The waiver is the owner's call |
| C. Native controls for the screens that matter most, and ImGui for the rest | Yes | Two UI stacks to keep in step; the native controls must still follow the shared-component rule |

**Recommendation:** start with option A, because it needs no waiver and its first step (the semantic
model) can be built and tested without a platform. Begin with the platform that has the most
users in the target audience once the owner says which that is; a first version on one platform
is a useful milestone, and an honest "one platform" status is better than a claim covering three.

## 4. The first steps that can be done without a platform

1. A `Semantics` value type in `src/ui/components` (role, name, value, state, bounds), with the
   shared button, text field, list and tree components reporting it. Tests: headless, comparing the
   snapshot of a component tree with expected values (no display needed).
2. A snapshot function on the shell that collects the model of the visible components, with a limit
   on its size, so a large project does not produce an unbounded tree.
3. A test that fails when a shared component reports no role or no name, so new components cannot
   silently skip the model.

Only after those, and with a platform machine available, the adapters.

## 5. Decisions for the owner

- **AccessKit:** allow the Rust library (with a documented waiver in AGENTS.md), or stay with
  per-platform adapters (option A)?
- **Platforms first:** which operating system and assistive technology (for example Windows with
  Narrator and NVDA, Linux with Orca, or macOS with VoiceOver) comes first?
- **Minimum bar:** is keyboard operation with a visible focus indicator the bar for the first
  release, with screen reader support to follow?

## 6. What is not claimed

- No screen reader works with Donkey today.
- The keyboard navigation in the UI tests is not accessibility support; it shows the focus model,
  not the assistive technology's view of it.
- The three adapters and the semantic model are not built. Their APIs have not been checked against
  current SDK documentation in this design.
