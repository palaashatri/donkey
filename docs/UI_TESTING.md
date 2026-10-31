# Scripted UI tests

`donkey --ui-script FILE [--ui-report FILE]` runs a test script inside the
real desktop application. Input reaches the application as SDL events
pushed with `SDL_PushEvent`, so it takes the same path as a person's
keyboard: SDL event queue → Dear ImGui SDL3 backend → widgets. Assertions
then read the workspace, the session and Dear ImGui's state. The process
exits 0 and prints `donkey ui-test: PASS <script>` when every assertion
held, otherwise it prints each `donkey ui-test: FAIL line N (...)` and
exits 1.

Scripts live in `tests/ui/*.donkeyui` and run under CTest as
`ui.script_*` when the build has `-DDONKEY_UI_SMOKE_TEST=ON` (Linux CI runs
them under Xvfb; the package jobs run them on every platform).

```bash
cmake --preset dev-linux -DDONKEY_UI_SMOKE_TEST=ON
cmake --build --preset dev-linux --parallel
xvfb-run -a ctest --preset dev-linux -R 'ui\.' --output-on-failure
# One script by hand, with its timing report:
xvfb-run -a build/dev-linux/apps/donkey/donkey --renderer software \
  --config-dir /tmp/donkey-ui --ui-script tests/ui/keyboard_ime.donkeyui \
  --ui-report /tmp/keyboard_ime.json build/dev-linux/tests/donkey_test_debuggee
```

## What the suite covers

| Script | Requirement | What it proves |
|---|---|---|
| `keyboard_ime` | A23, M1, M10 | Keyboard-only flow: `G` go-to by name, Enter, Alt+Left/Right history, `N` rename, `;` comment, Escape cancel, Ctrl+Z / Ctrl+Shift+Z. IME composition (`SDL_EVENT_TEXT_EDITING`) is not inserted; committed UTF-8 (`SDL_EVENT_TEXT_INPUT`) is; the IME candidate position lies in the focused field's window; the edit survives a focus loss/gain mid-entry; unknown names are reported, not navigated to. |
| `gallery_keyboard` | M0 | The shared button, badge, search and table components on a test screen (Help → Component Gallery), reached with Tab (status badges are not tab stops) and driven by typing. |
| `virtualization` | M2 | A 1,000,000-row table, jumped across in 300 frames: at most 200 rows submitted per frame, Dear ImGui's persistent storage grows by at most 16 entries, p95 frame time ≤ 33 ms. |
| `display_dpi_device` | M10, A22 | Display-scale changes rebuild style and font scale (2.0, 1.25, 1.0); a window left where no display is gets moved back when a display is removed; a lost graphics device is recreated (twice) with both Dear ImGui backends, and drawing continues. Runs on the software renderer and on the default renderer (SDL_GPU where available). |
| `layout_save` + `layout_restore` | A22 | A panel undocked in one run is still floating in the next: the dock layout persists in the per-user preference directory (or `--config-dir`). |
| `responsiveness` | DESIGN §12.2 | With 8 background analysis threads, input-to-frame p95 ≤ 50 ms. |

## Timing report

`--ui-report` writes `donkey.ui_report.v1` JSON with `count`, `p50`,
`p95`, `p99` and `max` (milliseconds, nearest-rank percentiles) for:

- `frame`: from `ImGui::NewFrame` to draw submission. It excludes
  present/vsync, which scripted runs disable.
- `input`: from `SDL_PushEvent` to submission of the frame that consumed the
  event. `input_under_load` is the subset recorded while `background_load`
  threads ran.
- `frame_interval`: wall time between frames, including present and the
  display server. This depends on the environment. Under Xvfb with the
  software renderer it was about 136 ms per frame on the 4-core sandbox where
  this harness was written, because the display server copies every frame.
  It says nothing about Donkey's own cost, and no threshold applies to it.
- Labels named by `measure` / `sweep`.

The reports are measurements of the machine they ran on. They are not
benchmarks of a reference machine (DESIGN §12.2 asks for one). The CI
artifacts keep them per platform.

## Limits

- A test cannot change a monitor's real DPI or unplug one. `scale` reports a
  new scale through the same event SDL sends. `display_removed` pushes the
  event after the window was moved where no display is. On window managers
  that refuse off-screen positions (macOS), that part is skipped and logged
  with `NOTE display-removal recovery not exercised`.
- Device loss is injected as `SDL_EVENT_RENDER_DEVICE_LOST`. A failed
  SDL_GPU command buffer takes the same recreation path at runtime. A real
  driver reset was not reproduced.
- SDL starts text input (and so the OS IME) only for the window that has
  keyboard focus. When the test window has none (some headless displays), the
  SDL side of `assert_text_input` is logged as not checked rather than
  passed.
- Screen readers are not covered: Dear ImGui exposes no accessibility tree.

## Commands

Input and environment (each waits 3 frames afterwards):
`key SPEC` (e.g. `g`, `enter`, `ctrl+shift+z`, `alt+left`, `semicolon`,
`tab`, `pagedown`), `text UTF-8…`, `ime_compose UTF-8…`, `focus_lost`,
`focus_gained`, `scale F`, `move_window X Y`, `display_removed`,
`device_lost`, `undock WINDOW`, `gallery_open`, `focus_window WINDOW`.

Flow: `frames N`, `wait_idle [ms]`, `measure LABEL FRAMES`,
`sweep LABEL FRAMES` (jumps the gallery table every frame),
`background_load [THREADS]`, `stop_background_load`, `storage_baseline`,
`require_window_off_display` … `end_require`, `dump_nav`, `quit`.

Assertions: `assert_selected ADDRESS|NAME`,
`assert_annotation rename|comment ADDRESS|NAME TEXT|-`,
`assert_focus WINDOW`, `assert_text_input 0|1`, `assert_ime_rect`,
`assert_scale F`, `assert_window_on_display`, `assert_graphics_resets N`,
`assert_floating WINDOW`, `assert_docked WINDOW`,
`assert_gallery_rows_max N`, `assert_gallery_selected ROW`,
`assert_gallery_scrolled_past ROW`, `assert_storage_growth_max N`,
`assert_p95 LABEL MS`, `assert_p99 LABEL MS`, `assert_no_error`.
