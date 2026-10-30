#pragma once

namespace donkey::ui::theme {

/// Apply the Donkey dark theme. `scale` bakes the host display scale into
/// sizes; the caller re-applies it when the display scale changes.
void apply(float scale);

}  // namespace donkey::ui::theme
