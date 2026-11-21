#include "donkey/project/typelib_apply.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "donkey/binary/elf_versions.h"

namespace donkey {
namespace {

enum class Space { None, Tag, Ordinary };

Space space_of(const TypeDefinition& type) {
  if (type.name.empty() || type.local) {
    return Space::None;  // unnamed, or a tag of a prototype's scope: not a file-scope name
  }
  switch (type.kind) {
    case TypeKind::Struct:
    case TypeKind::Union:
    case TypeKind::Enum:
      // `typedef struct { ... } item;` names the record with an ordinary name, not a tag.
      return type.typedef_named ? Space::Ordinary : Space::Tag;
    case TypeKind::Typedef:
    case TypeKind::Function:
      return Space::Ordinary;
    default:
      return Space::None;
  }
}

/// Compares a definition of the existing table with one of the library, through the types they
/// refer to. Two ids are the same when they name structurally equal types. Equality is a
/// conjunction, so a pair once visited in a query counts as equal for the rest of it (a recursive
/// record through a pointer, a shared subtree): any difference still makes the query false. Each
/// query visits each pair once at most, and spends a bounded budget; past it, the two are not
/// shown to be the same.
class ShapeComparer {
 public:
  ShapeComparer(const TypeTable& existing,
                const std::map<std::uint64_t, const TypeDefinition*>& library)
      : existing_(existing), library_(library) {}

  /// Whether the two definitions match. Starts a new query.
  bool equal(const TypeDefinition& a, const TypeDefinition& b) {
    visited_.clear();
    budget_ = kBudget;
    depth_ = 0;
    return same_definition(a, b);
  }

 private:
  static constexpr std::size_t kBudget = 100'000;
  /// How deep one comparison recurses (a chain of pointers, typedefs and members). Each level is
  /// two small frames, well under 1 KiB even in an ASan Debug build, so 256 levels stay far inside
  /// the smallest default thread stack Donkey runs on (512 KiB, macOS secondary threads); past it
  /// the two are not shown to be the same.
  static constexpr std::size_t kMaxDepth = 256;

  bool same(TypeId a, TypeId b) {
    if (!a.valid() || !b.valid()) {
      return a.valid() == b.valid();
    }
    if (!visited_.insert({a.value(), b.value()}).second) {
      return true;
    }
    if (budget_ == 0 || depth_ >= kMaxDepth) {
      return false;  // too much to compare: not shown to be the same
    }
    --budget_;
    ++depth_;
    const TypeDefinition* left = existing_.find(a);
    const auto right_entry = library_.find(b.value());
    const TypeDefinition* right = right_entry == library_.end() ? nullptr : right_entry->second;
    const bool equal = left != nullptr && right != nullptr && same_definition(*left, *right);
    --depth_;
    return equal;
  }

  bool same_definition(const TypeDefinition& a, const TypeDefinition& b) {
    if (a.kind != b.kind || a.size != b.size || a.is_signed != b.is_signed ||
        a.variadic != b.variadic || a.count != b.count || a.count_known != b.count_known ||
        a.alignment != b.alignment || a.complete != b.complete ||
        a.fields.size() != b.fields.size() || a.enumerators.size() != b.enumerators.size()) {
      return false;
    }
    // A named scalar is the same scalar by its name too (`long` and `long long` share a size).
    if ((a.kind == TypeKind::Integer || a.kind == TypeKind::Float) && a.name != b.name) {
      return false;
    }
    for (std::size_t i = 0; i < a.enumerators.size(); ++i) {
      if (a.enumerators[i].name != b.enumerators[i].name ||
          a.enumerators[i].value != b.enumerators[i].value) {
        return false;
      }
    }
    for (std::size_t i = 0; i < a.fields.size(); ++i) {
      const TypeField& x = a.fields[i];
      const TypeField& y = b.fields[i];
      if (a.kind != TypeKind::Function &&
          (x.name != y.name || x.offset != y.offset || x.bit_offset != y.bit_offset ||
           x.bit_size != y.bit_size || x.padding != y.padding)) {
        return false;
      }
      if (!same(x.type, y.type)) {
        return false;
      }
    }
    if (a.kind == TypeKind::Pointer || a.kind == TypeKind::Array || a.kind == TypeKind::Typedef ||
        a.kind == TypeKind::Function) {
      return same(a.target, b.target);
    }
    return true;
  }

  const TypeTable& existing_;
  const std::map<std::uint64_t, const TypeDefinition*>& library_;
  std::set<std::pair<std::uint64_t, std::uint64_t>> visited_;
  std::size_t budget_ = kBudget;
  std::size_t depth_ = 0;
};

std::string lower(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

}  // namespace

Result<TypeLibraryMerge> merge_type_library(const TypeTable& existing, const TypeLibrary& library,
                                            std::int64_t library_id) {
  TypeLibraryMerge merge;
  merge.table = existing;
  // The existing file-scope names, by name space.
  std::map<std::string, TypeId> existing_tags;
  std::map<std::string, TypeId> existing_ordinary;
  for (const TypeDefinition& type : existing.list()) {
    const Space space = space_of(type);
    if (space == Space::Tag) {
      existing_tags.emplace(type.name, type.id);
    } else if (space == Space::Ordinary) {
      existing_ordinary.emplace(type.name, type.id);
    }
  }
  std::map<std::uint64_t, const TypeDefinition*> library_types;
  for (const TypeDefinition& type : library.types) {
    library_types.emplace(type.id.value(), &type);
  }
  ShapeComparer comparer(existing, library_types);
  // Each library id to its id in the merged table, and the library ids whose name an existing,
  // different definition keeps.
  std::map<std::uint64_t, TypeId> moved;
  std::set<std::uint64_t> replaced_by_another;
  std::vector<const TypeDefinition*> candidates;
  for (const TypeDefinition& type : library.types) {
    const Space space = space_of(type);
    const auto& names = space == Space::Tag ? existing_tags : existing_ordinary;
    if (space != Space::None) {
      if (const auto found = names.find(type.name); found != names.end()) {
        const TypeDefinition* old = existing.find(found->second);
        // Another library's prototype of the same name is not this library's: each library keeps
        // its own, and the apply step picks the one whose library describes the import's file.
        const bool other_library_function =
            old != nullptr && type.kind == TypeKind::Function && old->kind == TypeKind::Function &&
            old->provenance == TypeProvenance::Library && old->library != library_id;
        if (!other_library_function) {
          moved[type.id.value()] = found->second;
          const bool differs = old == nullptr || !comparer.equal(*old, type);
          if (differs) {
            replaced_by_another.insert(type.id.value());
          }
          merge.collisions.push_back({type.name, found->second, differs});
          continue;
        }
      }
    }
    candidates.push_back(&type);
  }
  // A library type that refers, directly or through others, to a type the project defines
  // differently would change meaning if its references moved to the project's definition (a
  // parameter `item_t` that is `double` in the library and `unsigned long` in the project). Such a
  // type is not added, and neither is anything built on it: it is listed as dependent.
  std::set<std::uint64_t> dependent_ids;
  for (bool changed = true; changed;) {
    changed = false;
    for (const TypeDefinition* type : candidates) {
      if (dependent_ids.contains(type->id.value())) {
        continue;
      }
      const auto tainted = [&](TypeId id) {
        return replaced_by_another.contains(id.value()) || dependent_ids.contains(id.value());
      };
      bool depends = tainted(type->target);
      for (const TypeField& field : type->fields) {
        depends = depends || tainted(field.type);
      }
      if (depends) {
        dependent_ids.insert(type->id.value());
        changed = true;
      }
    }
  }
  std::uint64_t next = existing.next_id().value();
  std::vector<const TypeDefinition*> added;
  for (const TypeDefinition* type : candidates) {
    if (dependent_ids.contains(type->id.value())) {
      if (!type->name.empty()) {
        merge.dependent.push_back(type->name);
      }
      continue;
    }
    moved[type->id.value()] = TypeId{next++};
    added.push_back(type);
  }
  const auto remap = [&moved](TypeId id) {
    const auto found = moved.find(id.value());
    return found == moved.end() ? id : found->second;
  };
  for (const TypeDefinition* type : added) {
    TypeDefinition copy = *type;
    copy.id = remap(copy.id);
    copy.target = remap(copy.target);
    for (TypeField& field : copy.fields) {
      field.type = remap(field.type);
    }
    copy.provenance = TypeProvenance::Library;
    copy.library = library_id;
    if (copy.kind == TypeKind::Function && !copy.name.empty() && space_of(copy) != Space::None) {
      merge.functions[copy.name].push_back(copy.id);
    }
    merge.table.put(std::move(copy));
    ++merge.added;
  }
  if (auto valid = merge.table.validate(); !valid) {
    return make_error<TypeLibraryMerge>(
        Status::InvalidInput, "typelib_apply.invalid",
        "the merged type table is not valid: " + valid.diagnostic().message);
  }
  for (const TypeDefinition& type : library.types) {
    if (dependent_ids.contains(type.id.value())) {
      continue;
    }
    const Space space = space_of(type);
    if (space == Space::Tag) {
      merge.tags.emplace(type.name, remap(type.id));
    } else if (space == Space::Ordinary) {
      merge.ordinary.emplace(type.name, remap(type.id));
    }
  }
  return merge;
}

std::string import_match_name(std::string_view name, bool mach_o) {
  std::string out(name.substr(0, name.find('@')));
  if (mach_o && !out.empty() && out.front() == '_') {
    out.erase(0, 1);
  }
  return out;
}

ImageAbi image_abi(std::string_view format, std::string_view architecture, unsigned bits) {
  ImageAbi out;
  out.architecture = std::string(architecture);
  // Only 64-bit code: an x32 ELF image (EM_X86_64 in ELFCLASS32) is ILP32, which no library
  // format value describes.
  if ((architecture != "x86_64" && architecture != "aarch64") || bits != 64) {
    return out;
  }
  if (format == "ELF") {
    out.abi = architecture == "x86_64" ? "sysv" : "aapcs64";
    out.data_model = "LP64";
  } else if (format == "PE" && architecture == "x86_64") {
    out.platform = "windows";
    out.abi = "win64";
    out.data_model = "LLP64";
  } else if (format == "Mach-O") {
    out.platform = "macos";
    out.abi = architecture == "x86_64" ? "sysv" : "aapcs64";
    out.data_model = "LP64";
  }
  return out;
}

std::string library_misfit(const TypeLibraryRecord& library, const ImageAbi& image) {
  const std::string name = library.library + " " + library.library_version;
  if (image.abi.empty()) {
    return "no type library describes a " + image.architecture + " image of this format";
  }
  if (library.architecture != image.architecture || library.abi != image.abi ||
      library.data_model != image.data_model) {
    return name + " is for " + library.architecture + " " + library.abi + " " + library.data_model +
           ", the image is " + image.architecture + " " + image.abi + " " + image.data_model;
  }
  if (!image.platform.empty() && library.platform != image.platform) {
    return name + " is for " + library.platform + ", the image is for " + image.platform;
  }
  if (image.platform.empty() && library.platform != "linux" && library.platform != "freebsd") {
    return name + " is for " + library.platform + ", the image is an ELF image";
  }
  return {};
}

std::vector<ImportSite> import_sites(const BinaryImage& image, std::span<const std::byte> data,
                                     const AnalysisResult& analysis,
                                     const ElfLibrarySearch& search) {
  std::vector<ImportSite> sites;
  for (const Function& function : analysis.functions) {
    if (!function.import_name.empty()) {
      sites.push_back(ImportSite{function.import_name, function.address, {}, {}, {}});
    }
  }
  if (sites.empty()) {
    return sites;
  }
  if (image.format == BinaryFormat::Elf) {
    auto references = read_import_references(image, data);
    if (!references) {
      for (ImportSite& site : sites) {
        site.unbound = "the symbol version table: " + references.diagnostic().message;
      }
      return sites;
    }
    // Each (version, hidden) form a name is imported with: every one must bind.
    std::map<std::string, std::set<std::pair<std::string, bool>>> forms;
    std::set<std::string> unresolved;
    for (const ElfImportReference& reference : references.value()) {
      forms[reference.name].emplace(reference.version, reference.hidden);
      if (reference.unresolved) {
        unresolved.insert(reference.name);
      }
    }
    const ElfLoadScope scope = ElfLoadScope::build(image, data, search);
    for (ImportSite& site : sites) {
      const std::string name = import_match_name(site.name);
      const auto found = forms.find(name);
      if (found == forms.end()) {
        site.unbound = name + " is not an imported dynamic symbol";
        continue;
      }
      for (const auto& [version, hidden] : found->second) {
        site.versions.push_back(version);
      }
      if (unresolved.contains(name)) {
        site.unbound = name + ": its symbol version could not be read";
        continue;
      }
      std::vector<std::string> providers;
      for (const auto& [version, hidden] : found->second) {
        const ElfBinding binding = scope.lookup(name, version, hidden);
        if (binding.outcome == ElfBinding::Outcome::Unknown) {
          site.unbound = binding.reason;
          break;
        }
        if (binding.outcome == ElfBinding::Outcome::NotDefined) {
          site.unbound = name + " is defined by no library of the load scope";
          break;
        }
        if (binding.library == scope.image_index()) {
          site.unbound = name + " binds to the image itself";
          break;
        }
        const ElfScopeLibrary& library = scope.libraries()[binding.library];
        providers.push_back(library.soname.empty()
                                ? library.path.substr(library.path.find_last_of('/') + 1)
                                : library.soname);
      }
      if (site.unbound.empty()) {
        site.providers = std::move(providers);
      }
    }
  } else if (image.format == BinaryFormat::Pe) {
    // A PE thunk jumps through one IAT slot, and the import directory entry of that slot names
    // its DLL and says whether it is imported by ordinal (not the display name: a function may
    // well be named `ordinal_5`).
    std::map<std::uint64_t, const Symbol*> by_slot;
    for (const Symbol& symbol : image.symbols) {
      if (symbol.imported) {
        by_slot.emplace(symbol.address, &symbol);
      }
    }
    std::map<std::uint64_t, std::uint64_t> slot_of;
    for (const Function& function : analysis.functions) {
      if (!function.import_name.empty()) {
        slot_of.emplace(function.address, function.import_slot);
      }
    }
    for (ImportSite& site : sites) {
      site.versions.emplace_back();
      const auto slot = slot_of.find(site.address);
      const auto symbol = slot == slot_of.end() ? by_slot.end() : by_slot.find(slot->second);
      if (symbol == by_slot.end() || symbol->second->name != site.name) {
        site.unbound = site.name +
                       ": the IAT slot its thunk jumps through is not in the import "
                       "directory";
      } else if (symbol->second->module.empty()) {
        site.unbound = site.name + ": the import directory names no DLL for it";
      } else {
        site.by_ordinal = symbol->second->by_ordinal;
        site.providers.push_back(symbol->second->module);
      }
    }
  } else {
    for (ImportSite& site : sites) {
      site.unbound = std::string(format_name(image.format)) +
                     " import stubs are not bound to their libraries yet";
    }
  }
  return sites;
}

std::vector<ImportPrototype> match_import_prototypes(const std::vector<ImportSite>& sites,
                                                     const TypeLibraryMerge& merge) {
  std::vector<ImportPrototype> out;
  out.reserve(sites.size());
  for (const ImportSite& site : sites) {
    ImportPrototype entry;
    entry.import = site.name;
    const std::string name = import_match_name(site.name);
    std::set<std::string> versions(site.versions.begin(), site.versions.end());
    if (const std::size_t at = site.name.find('@'); at != std::string::npos) {
      versions.insert(site.name.substr(at + 1 + (site.name.compare(at, 2, "@@") == 0 ? 1 : 0)));
    }
    if (site.by_ordinal) {
      entry.reason = "ordinal import";
    } else if (versions.size() > 1) {
      entry.reason = "ambiguous";
    } else {
      // Every library function of the name, in id order: one per library that declares it.
      std::vector<TypeId> found;
      if (const auto listed = merge.functions.find(name); listed != merge.functions.end()) {
        found = listed->second;
      }
      if (const auto ordinary = merge.ordinary.find(name);
          ordinary != merge.ordinary.end() &&
          std::find(found.begin(), found.end(), ordinary->second) == found.end()) {
        found.push_back(ordinary->second);
      }
      for (const TypeId id : found) {
        const TypeDefinition* type = merge.table.find(id);
        if (type != nullptr && type->kind == TypeKind::Function &&
            type->provenance == TypeProvenance::Library) {
          entry.candidates.push_back(id);
        }
      }
      if (entry.candidates.empty()) {
        entry.reason = "no prototype";
      } else {
        entry.prototype = entry.candidates.front();
      }
    }
    out.push_back(std::move(entry));
  }
  return out;
}

TypeLibraryMerge library_prototypes(const TypeTable& table) {
  TypeLibraryMerge out;
  out.table = table;
  for (const TypeDefinition& type : table.list()) {
    if (type.kind == TypeKind::Function && type.provenance == TypeProvenance::Library &&
        !type.name.empty() && !type.local) {
      out.functions[type.name].push_back(type.id);
    }
  }
  return out;
}

namespace {

/// apply_library_prototypes inside its write transaction.
Result<std::vector<LibraryPrototypeApplication>> apply_library_prototypes_now(
    Project& project, std::int64_t image_id, const std::vector<ImportSite>& sites,
    const ImageAbi& image) {
  auto table = project.types();
  if (!table) {
    return table.diagnostic();
  }
  auto existing = project.type_applications(image_id);
  if (!existing) {
    return existing.diagnostic();
  }
  auto libraries = project.type_libraries();
  if (!libraries) {
    return libraries.diagnostic();
  }
  std::map<std::int64_t, const TypeLibraryRecord*> library_of;
  for (const TypeLibraryRecord& record : libraries.value()) {
    library_of.emplace(record.id, &record);
  }
  std::map<std::uint64_t, TypeProvenance> prototype_source;
  for (const TypeApplication& application : existing.value()) {
    if (application.kind == TypeApplicationKind::FunctionPrototype) {
      prototype_source[application.address] = application.source;
    }
  }
  const TypeLibraryMerge prototypes = library_prototypes(table.value());
  const std::vector<ImportPrototype> matched = match_import_prototypes(sites, prototypes);
  std::vector<LibraryPrototypeApplication> out;
  out.reserve(sites.size());
  for (std::size_t index = 0; index < sites.size(); ++index) {
    const ImportSite& site = sites[index];
    LibraryPrototypeApplication entry;
    entry.import = site.name;
    entry.address = site.address;
    entry.reason = matched[index].reason;
    if (!entry.reason.empty()) {
      out.push_back(std::move(entry));
      continue;
    }
    // The first candidate whose library fits the image and describes the import's file applies;
    // when none does, the first candidate's reason is reported.
    TypeId chosen{};
    std::string first_reason;
    std::string first_library;
    for (const TypeId candidate : matched[index].candidates) {
      const TypeDefinition* type = table.value().find(candidate);
      const auto record = type == nullptr ? library_of.end() : library_of.find(type->library);
      std::string reason;
      std::string library_name;
      if (record == library_of.end()) {
        reason = "the library that brought the prototype is not recorded";
      } else {
        const TypeLibraryRecord& library = *record->second;
        library_name = library.library + " " + library.library_version;
        if (std::string misfit = library_misfit(library, image); !misfit.empty()) {
          reason = std::move(misfit);
        } else if (!site.unbound.empty()) {
          reason = "provider not shown: " + site.unbound;
        } else if (site.providers.empty()) {
          reason = "provider not shown";
        } else {
          for (const std::string& provider : site.providers) {
            const bool described = std::any_of(
                library.provides.begin(), library.provides.end(), [&](const std::string& file) {
                  return image.platform == "windows" ? lower(file) == lower(provider)
                                                     : file == provider;
                });
            if (!described) {
              reason = "bound to " + provider + ", which " + library_name + " does not describe";
              break;
            }
          }
        }
      }
      if (reason.empty()) {
        chosen = candidate;
        entry.library = library_name;
        break;
      }
      if (first_reason.empty()) {
        first_reason = std::move(reason);
        first_library = std::move(library_name);
      }
    }
    if (!chosen.valid()) {
      entry.reason = first_reason;
      entry.library = first_library;
    }
    if (entry.reason.empty()) {
      const auto source = prototype_source.find(entry.address);
      if (source != prototype_source.end() && source->second != TypeProvenance::Library) {
        entry.reason = std::string("kept: ") + type_provenance_name(source->second);
      } else {
        // The store keeps a prototype of another source, and says so (the read above and this
        // write are one transaction, so it would be one this call made itself).
        std::optional<TypeProvenance> kept;
        auto applied =
            project.set_type_application(image_id, TypeApplicationKind::FunctionPrototype,
                                         entry.address, chosen, TypeProvenance::Library, &kept);
        if (!applied) {
          return applied.diagnostic();
        }
        if (kept) {
          entry.reason = std::string("kept: ") + type_provenance_name(*kept);
        } else {
          entry.prototype = chosen;
        }
      }
    }
    out.push_back(std::move(entry));
  }
  return out;
}

}  // namespace

Result<std::vector<LibraryPrototypeApplication>> apply_library_prototypes(
    Project& project, std::int64_t image_id, const std::vector<ImportSite>& sites,
    const ImageAbi& image) {
  // The type table, the applications and the libraries are read, and the prototypes written, in
  // one write transaction: a candidate is checked against the table its id is written into.
  std::vector<LibraryPrototypeApplication> out;
  auto done = project.write_transaction([&]() -> Result<void> {
    auto applied = apply_library_prototypes_now(project, image_id, sites, image);
    if (!applied) {
      return make_void_error(applied.diagnostic().status, applied.diagnostic().code,
                             applied.diagnostic().message);
    }
    out = std::move(applied.value());
    return Result<void>();
  });
  if (!done) {
    return done.diagnostic();
  }
  return out;
}

}  // namespace donkey
