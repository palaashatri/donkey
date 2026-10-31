#pragma once

namespace donkey::ui::theme {

/// Apply the Donkey dark theme. `scale` bakes the host display scale into
/// sizes and the font scale; call it again when the display scale changes
/// (the monospace font is loaded only the first time).
void apply(float scale);

}  // namespace donkey::ui::theme
