#pragma once

// Calls and jumps from one image of a link set into an import that another image provides
// (G15-T2). Reads the analysis of each image; nothing is run and no image is changed.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/link.h"
#include "donkey/core/result.h"

namespace donkey {

/// One call or jump in an image of the link set that goes through one of its PLT stubs.
struct ImportCall {
  std::size_t importer = 0;               ///< index into the link inputs
  std::uint64_t from = 0;                 ///< address of the call or jump instruction
  XrefKind kind = XrefKind::Unknown;      ///< Call or Jump
  std::uint64_t stub = 0;                 ///< the importer's PLT stub it goes through
  std::string name;                       ///< the imported name the stub calls
  std::size_t provider = kUnboundImport;  ///< the input whose export it binds to, or unbound
  std::uint64_t to = 0;                   ///< the provider's address for the export; 0 if unbound
};

/// Binds each call and jump through a PLT stub to the export that `linked` chose for that import,
/// so a call to `provided_fn@plt` names the provider's `provided_fn`. An unbound import is listed
/// with `provider` set to kUnboundImport rather than dropped. `analyses[i]` must be the analysis of
/// `inputs[i]`. Not listed: calls through a GOT slot (`call [rip+x]`, as -fno-plt code makes) and
/// imports used as data pointers. A partial analysis can miss call sites, which the caller must
/// report.
[[nodiscard]] Result<std::vector<ImportCall>> resolve_import_calls(
    std::span<const LinkInput> inputs, const LinkResult& linked,
    std::span<const AnalysisResult> analyses);

}  // namespace donkey
