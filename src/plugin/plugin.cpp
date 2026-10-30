#include "donkey/plugin/plugin.h"

#include <dlfcn.h>

#include <vector>

namespace donkey {

Result<PluginManifest> PluginHost::inspect_manifest(const std::string& library_path) {
  void* handle = dlopen(library_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    const char* err = dlerror();
    return Diagnostic::make(Status::InvalidInput, "plugin.load_failed",
                            err ? err : "Failed to dlopen plugin library");
  }

  void* sym = dlsym(handle, DONKEY_PLUGIN_ENTRY_SYMBOL);
  if (!sym) {
    dlclose(handle);
    return Diagnostic::make(Status::InvalidInput, "plugin.missing_entry_symbol",
                            "Plugin missing 'donkey_plugin_entry' symbol export");
  }

  auto entry_fn = reinterpret_cast<DonkeyPluginEntryFn>(sym);
  const DonkeyPluginDescriptor* desc = entry_fn();
  if (!desc) {
    dlclose(handle);
    return Diagnostic::make(Status::InvalidInput, "plugin.null_descriptor",
                            "Plugin entry function returned null descriptor");
  }

  if (desc->struct_size != sizeof(DonkeyPluginDescriptor)) {
    dlclose(handle);
    return Diagnostic::make(Status::InvalidInput, "plugin.struct_size_mismatch",
                            "Plugin descriptor size mismatch: expected " +
                                std::to_string(sizeof(DonkeyPluginDescriptor)) + ", got " +
                                std::to_string(desc->struct_size));
  }

  if (desc->abi_version_major != DONKEY_PLUGIN_ABI_VERSION_MAJOR) {
    uint32_t got_major = desc->abi_version_major;
    dlclose(handle);
    return Diagnostic::make(Status::InvalidInput, "plugin.abi_version_mismatch",
                            "Incompatible plugin ABI version: expected major " +
                                std::to_string(DONKEY_PLUGIN_ABI_VERSION_MAJOR) + ", got " +
                                std::to_string(got_major));
  }

  PluginManifest manifest{
      .id = desc->id ? desc->id : "",
      .name = desc->name ? desc->name : "",
      .version = desc->version ? desc->version : "",
      .author = desc->author ? desc->author : "",
      .description = desc->description ? desc->description : "",
      .abi_version_major = desc->abi_version_major,
      .abi_version_minor = desc->abi_version_minor,
      .requested_capabilities = desc->requested_capabilities,
  };

  dlclose(handle);
  return manifest;
}

Result<PluginExecutionResult> PluginHost::execute_trusted(const std::string& library_path,
                                                          const std::string& input_json,
                                                          uint64_t granted_capabilities) {
  void* handle = dlopen(library_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    const char* err = dlerror();
    return Diagnostic::make(Status::InvalidInput, "plugin.load_failed",
                            err ? err : "Failed to dlopen plugin library");
  }

  void* sym = dlsym(handle, DONKEY_PLUGIN_ENTRY_SYMBOL);
  if (!sym) {
    dlclose(handle);
    return Diagnostic::make(Status::InvalidInput, "plugin.missing_entry_symbol",
                            "Plugin missing 'donkey_plugin_entry' symbol export");
  }

  auto entry_fn = reinterpret_cast<DonkeyPluginEntryFn>(sym);
  const DonkeyPluginDescriptor* desc = entry_fn();
  if (!desc) {
    dlclose(handle);
    return Diagnostic::make(Status::InvalidInput, "plugin.null_descriptor",
                            "Plugin entry function returned null descriptor");
  }

  if (desc->struct_size != sizeof(DonkeyPluginDescriptor)) {
    dlclose(handle);
    return Diagnostic::make(Status::InvalidInput, "plugin.struct_size_mismatch",
                            "Plugin descriptor size mismatch");
  }

  if (desc->abi_version_major != DONKEY_PLUGIN_ABI_VERSION_MAJOR) {
    uint32_t got_major = desc->abi_version_major;
    dlclose(handle);
    return Diagnostic::make(Status::InvalidInput, "plugin.abi_version_mismatch",
                            "Incompatible plugin ABI version: expected major " +
                                std::to_string(DONKEY_PLUGIN_ABI_VERSION_MAJOR) + ", got " +
                                std::to_string(got_major));
  }

  if ((desc->requested_capabilities & ~granted_capabilities) != 0) {
    dlclose(handle);
    return Diagnostic::make(Status::PermissionDenied, "plugin.capability_denied",
                            "Plugin requested capabilities that have not been granted by user");
  }

  if (desc->init) {
    int init_rc = desc->init();
    if (init_rc != 0) {
      dlclose(handle);
      return Diagnostic::make(Status::InternalError, "plugin.init_failed",
                              "Plugin init() returned error code " + std::to_string(init_rc));
    }
  }

  std::vector<char> out_buf(65536, 0);
  int exec_rc = 0;
  if (desc->execute) {
    exec_rc = desc->execute(input_json.c_str(), out_buf.data(), out_buf.size());
  }

  if (desc->shutdown) {
    desc->shutdown();
  }

  dlclose(handle);

  PluginExecutionResult res;
  res.exit_code = exec_rc;
  if (exec_rc == 0) {
    res.success = true;
    res.output_json = out_buf.data();
  } else {
    res.success = false;
    res.error_code = "plugin.execution_failed";
    res.error_message = "Plugin execute() returned non-zero code " + std::to_string(exec_rc);
  }
  return res;
}

}  // namespace donkey
