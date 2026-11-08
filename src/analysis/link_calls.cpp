#include "donkey/analysis/link_calls.h"

#include <map>
#include <string>
#include <utility>

#include "donkey/binary/plt.h"

namespace donkey {

Result<std::vector<ImportCall>> resolve_import_calls(std::span<const LinkInput> inputs,
                                                     const LinkResult& linked,
                                                     std::span<const AnalysisResult> analyses) {
  if (analyses.size() != inputs.size()) {
    return make_error<std::vector<ImportCall>>(
        Status::InvalidInput, "link.analyses_mismatch",
        "one analysis is needed for each link input, in the same order");
  }
  std::vector<ImportCall> calls;
  for (std::size_t importer = 0; importer < inputs.size(); ++importer) {
    if (inputs[importer].image == nullptr) {
      continue;
    }
    const std::map<std::uint64_t, std::string> stubs =
        plt_stub_imports(*inputs[importer].image, inputs[importer].data);
    if (stubs.empty()) {
      continue;
    }
    // The export each of this importer's imports is bound to, by name.
    std::map<std::string, const ImportBinding*> bound;
    for (const ImportBinding& binding : linked.bindings) {
      if (binding.importer == importer) {
        bound.emplace(binding.name, &binding);
      }
    }
    for (const Xref& xref : analyses[importer].xrefs) {
      if (xref.kind != XrefKind::Call && xref.kind != XrefKind::Jump) {
        continue;
      }
      const auto stub = stubs.find(xref.to);
      if (stub == stubs.end()) {
        continue;
      }
      ImportCall call;
      call.importer = importer;
      call.from = xref.from;
      call.kind = xref.kind;
      call.stub = xref.to;
      call.name = stub->second;
      if (const auto found = bound.find(call.name); found != bound.end()) {
        if (found->second->provider != kUnboundImport) {
          call.provider = found->second->provider;
          call.to = found->second->address;
        }
      }
      calls.push_back(std::move(call));
    }
  }
  return calls;
}

}  // namespace donkey
