include(GoogleTest)

add_library(test_plugin_valid MODULE fixtures/plugins/valid_plugin.c)
target_include_directories(test_plugin_valid PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_library(test_plugin_bad_abi MODULE fixtures/plugins/bad_abi_plugin.c)
target_include_directories(test_plugin_bad_abi PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_library(test_plugin_crash MODULE fixtures/plugins/crash_plugin.c)
target_include_directories(test_plugin_crash PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_library(test_plugin_hang MODULE fixtures/plugins/hang_plugin.c)
target_include_directories(test_plugin_hang PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_library(test_plugin_ctor_crash MODULE fixtures/plugins/ctor_crash_plugin.c)
target_include_directories(test_plugin_ctor_crash PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_library(test_plugin_non_terminated MODULE fixtures/plugins/non_terminated_plugin.c)
target_include_directories(test_plugin_non_terminated PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_executable(donkey_unit_tests
  unit/acceptance_test.cpp
  unit/binary_test.cpp
  unit/cfg_test.cpp
  unit/debug_test.cpp
  unit/decode_test.cpp
  unit/foundation_test.cpp
  unit/ir_test.cpp
  unit/patch_test.cpp
  unit/plugin_test.cpp
  unit/project_test.cpp
  unit/session_test.cpp
)
target_link_libraries(donkey_unit_tests PRIVATE donkey::session donkey::ir donkey::debug donkey::patch donkey::plugin GTest::gtest_main)
target_compile_definitions(donkey_unit_tests PRIVATE
  DONKEY_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
  TEST_PLUGIN_VALID_PATH="$<TARGET_FILE:test_plugin_valid>"
  TEST_PLUGIN_BAD_ABI_PATH="$<TARGET_FILE:test_plugin_bad_abi>"
  TEST_PLUGIN_CRASH_PATH="$<TARGET_FILE:test_plugin_crash>"
  TEST_PLUGIN_HANG_PATH="$<TARGET_FILE:test_plugin_hang>"
  TEST_PLUGIN_CTOR_CRASH_PATH="$<TARGET_FILE:test_plugin_ctor_crash>"
  TEST_PLUGIN_NON_TERMINATED_PATH="$<TARGET_FILE:test_plugin_non_terminated>"
)
add_dependencies(donkey_unit_tests test_plugin_valid test_plugin_bad_abi test_plugin_crash test_plugin_hang test_plugin_ctor_crash test_plugin_non_terminated)
donkey_apply_warnings(donkey_unit_tests)

gtest_discover_tests(donkey_unit_tests DISCOVERY_TIMEOUT 30)

add_test(NAME cli.version COMMAND donkey-cli --version)
set_tests_properties(cli.version PROPERTIES PASS_REGULAR_EXPRESSION "donkey-cli ${PROJECT_VERSION}")

add_test(NAME cli.help COMMAND donkey-cli --help)
set_tests_properties(cli.help PROPERTIES PASS_REGULAR_EXPRESSION "Usage:")

add_test(NAME cli.rejects_unknown_argument COMMAND donkey-cli --definitely-not-a-flag)
set_tests_properties(cli.rejects_unknown_argument PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli.info_elf_json
         COMMAND donkey-cli info ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.info_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"schema_version\": 1.*\"format\": \"ELF\"")

add_test(NAME cli.info_isolated_json
         COMMAND donkey-cli info ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --isolate --json)
set_tests_properties(cli.info_isolated_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"schema_version\": 1.*\"format\": \"ELF\"")

add_test(NAME cli.info_pe_human
         COMMAND donkey-cli info ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-pe-x86_64.exe)
set_tests_properties(cli.info_pe_human PROPERTIES
  PASS_REGULAR_EXPRESSION "ExitProcess")

add_test(NAME cli.info_macho_json
         COMMAND donkey-cli info ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-macho-arm64 --json)
set_tests_properties(cli.info_macho_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"architecture\": \"aarch64\"")

add_test(NAME cli.info_macho_i386_json
         COMMAND donkey-cli info ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-macho-i386 --json)
set_tests_properties(cli.info_macho_i386_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"format_detail\": \"Mach-O 32 \\(MH_EXECUTE\\)\".*\"architecture\": \"x86\"")

add_test(NAME cli.info_macho_fat_x86_json
         COMMAND donkey-cli info ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-macho-fat
                 --arch x86 --json)
set_tests_properties(cli.info_macho_fat_x86_json PROPERTIES
  PASS_REGULAR_EXPRESSION
    "\"architecture\": \"x86\".*\"fat_architectures\": \\[\"x86\", \"aarch64\"\\]")

add_test(NAME cli.disasm_raw_x86_64_json
         COMMAND donkey-cli disasm ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64
                 --raw --arch x86_64 --base 0x1000 --address 0x1100 --count 3 --json)
set_tests_properties(cli.disasm_raw_x86_64_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"start\": \"0x1100\".*\"mnemonic\": \"push\"")

add_test(NAME cli.info_missing_file COMMAND donkey-cli info /definitely/not/here)
set_tests_properties(cli.info_missing_file PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli.disasm_elf_json
         COMMAND donkey-cli disasm ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.disasm_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"mnemonic\": \"push\".*\"mnemonic\": \"call\".*\"target\": \"0x400109\"")

add_test(NAME cli.disasm_macho_human
         COMMAND donkey-cli disasm ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-macho-arm64)
set_tests_properties(cli.disasm_macho_human PROPERTIES
  PASS_REGULAR_EXPRESSION "0x100000f10 +c0035fd6 +ret")

add_test(NAME cli.strings_elf_json
         COMMAND donkey-cli strings ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.strings_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"encoding\": \"ascii\", \"text\": \"hello world\"")

add_test(NAME cli.functions_elf_json
         COMMAND donkey-cli functions ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.functions_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"name\": \"_start\".*\"address\": \"0x400100\"")

add_test(NAME cli.xrefs_elf_json
         COMMAND donkey-cli xrefs ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.xrefs_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"from\": \"0x400104\", \"to\": \"0x400109\", \"kind\": \"call\"")

add_test(NAME cli.analyze_elf_json
         COMMAND donkey-cli analyze ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.analyze_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"instructions\": 10, \"functions\": 2, \"xrefs\": 1, \"strings\": 1")

add_test(NAME cli.analyze_rejects_unknown_flag
         COMMAND donkey-cli analyze ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --nope)
set_tests_properties(cli.analyze_rejects_unknown_flag PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli.disasm_rejects_bad_address
         COMMAND donkey-cli disasm ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --address zz)
set_tests_properties(cli.disasm_rejects_bad_address PROPERTIES WILL_FAIL TRUE)

# ---------------------------------------------------------------------------
# Desktop shell smoke test. Default OFF: it needs a real display and GPU, so
# headless CI must never run it. Enable with -DDONKEY_UI_SMOKE_TEST=ON.
# ---------------------------------------------------------------------------

if(DONKEY_BUILD_UI AND DONKEY_UI_SMOKE_TEST)
  add_test(NAME ui.smoke_loads_elf
           COMMAND donkey ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64
                   --exit-after-frames 20)
  set_tests_properties(ui.smoke_loads_elf PROPERTIES TIMEOUT 120)

  add_test(NAME ui.smoke_rejects_unknown_option COMMAND donkey --nope)
  set_tests_properties(ui.smoke_rejects_unknown_option PROPERTIES WILL_FAIL TRUE)
endif()

add_test(NAME cli.cfg_elf_json
         COMMAND donkey-cli cfg ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.cfg_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"address\": \"0x400100\".*\"kind\": \"call\"")

add_test(NAME cli.decompile_elf_json
         COMMAND donkey-cli decompile ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.decompile_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"name\": \"_start\".*\"status\": \"Complete\".*u64 _start")

add_test(NAME cli.decompile_elf_function_filter
         COMMAND donkey-cli decompile ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64
                 --function 0x400100 --json)
set_tests_properties(cli.decompile_elf_function_filter PROPERTIES
  PASS_REGULAR_EXPRESSION "\"name\": \"_start\".*\"pseudocode\"")

add_test(NAME cli.decompile_rejects_unknown_function
         COMMAND donkey-cli decompile ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64
                 --function 0x1234)
set_tests_properties(cli.decompile_rejects_unknown_function PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli.decompile_macho_aarch64
         COMMAND donkey-cli decompile ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-macho-arm64 --json)
set_tests_properties(cli.decompile_macho_aarch64 PROPERTIES
  PASS_REGULAR_EXPRESSION "\"name\": \"_main\".*\"pseudocode\":.*sp - 0x10")

add_test(NAME cli.decompile_elf_i386
         COMMAND donkey-cli decompile ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-i386 --json)
set_tests_properties(cli.decompile_elf_i386 PROPERTIES
  PASS_REGULAR_EXPRESSION
    "\"name\": \"_start\".*\"status\": \"Complete\".*u32 _start\\(void\\).*esp = esp - 0x4")

# ---------------------------------------------------------------------------
# Project persistence CLI.
# ---------------------------------------------------------------------------

set(DONKEY_CLI_PROJECT_DB "${CMAKE_CURRENT_BINARY_DIR}/cli-project-save.db")

add_test(NAME cli.project_save_elf_json
         COMMAND donkey-cli project save ${DONKEY_CLI_PROJECT_DB}
                 ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.project_save_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"schema\": 3.*\"integrity\": true.*\"sha256\"")

add_test(NAME cli.project_info_elf_json
         COMMAND donkey-cli project info ${DONKEY_CLI_PROJECT_DB} --json)
set_tests_properties(cli.project_info_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"project_schema\": 3.*\"integrity\": true.*\"format\": \"ELF\""
  DEPENDS cli.project_save_elf_json)

if(DONKEY_BUILD_UI AND DONKEY_UI_SMOKE_TEST)
  add_test(NAME ui.smoke_loads_project
           COMMAND donkey --project ${DONKEY_CLI_PROJECT_DB} --exit-after-frames 20)
  set_tests_properties(ui.smoke_loads_project PROPERTIES
    TIMEOUT 120
    DEPENDS cli.project_save_elf_json)
endif()

add_test(NAME cli.project_info_rejects_non_database
         COMMAND donkey-cli project info
                 ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64)
set_tests_properties(cli.project_info_rejects_non_database PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli.project_info_rejects_missing
         COMMAND donkey-cli project info ${CMAKE_CURRENT_BINARY_DIR}/does-not-exist.db)
set_tests_properties(cli.project_info_rejects_missing PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli.project_rejects_unknown_subcommand COMMAND donkey-cli project nope)

set_tests_properties(cli.project_rejects_unknown_subcommand PROPERTIES WILL_FAIL TRUE)

# ---------------------------------------------------------------------------
# Persisted annotations (schema v3).
# ---------------------------------------------------------------------------

set(DONKEY_CLI_ANN_DB "${CMAKE_CURRENT_BINARY_DIR}/cli-project-annotations.db")

add_test(NAME cli.project_annotation_save
         COMMAND donkey-cli project save ${DONKEY_CLI_ANN_DB}
                 ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.project_annotation_save PROPERTIES
  PASS_REGULAR_EXPRESSION "\"schema\": 3.*\"image_id\": 1")

add_test(NAME cli.project_rename
         COMMAND donkey-cli project rename ${DONKEY_CLI_ANN_DB} 1 0x400100 entry_point)
set_tests_properties(cli.project_rename PROPERTIES DEPENDS cli.project_annotation_save)

add_test(NAME cli.project_comment
         COMMAND donkey-cli project comment ${DONKEY_CLI_ANN_DB} 1 0x400104 "calls the helper")
set_tests_properties(cli.project_comment PROPERTIES DEPENDS cli.project_annotation_save)

add_test(NAME cli.project_bookmark
         COMMAND donkey-cli project bookmark ${DONKEY_CLI_ANN_DB} 1 0x400100 "important")
set_tests_properties(cli.project_bookmark PROPERTIES DEPENDS cli.project_annotation_save)

add_test(NAME cli.project_annotations_json
         COMMAND donkey-cli project annotations ${DONKEY_CLI_ANN_DB} 1 --json)
set_tests_properties(cli.project_annotations_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"kind\": \"bookmark\".*\"address\": \"0x400100\".*\"kind\": \"rename\".*\"text\": \"entry_point\".*\"kind\": \"comment\""
  DEPENDS "cli.project_rename;cli.project_comment;cli.project_bookmark")

add_test(NAME cli.project_annotation_clear
         COMMAND donkey-cli project rename ${DONKEY_CLI_ANN_DB} 1 0x400100 --clear)
set_tests_properties(cli.project_annotation_clear PROPERTIES
  DEPENDS "cli.project_rename;cli.project_comment;cli.project_bookmark")

add_test(NAME cli.project_annotations_after_clear
         COMMAND donkey-cli project annotations ${DONKEY_CLI_ANN_DB} 1 --json)
set_tests_properties(cli.project_annotations_after_clear PROPERTIES
  PASS_REGULAR_EXPRESSION "\"kind\": \"comment\""
  FAIL_REGULAR_EXPRESSION "entry_point"
  DEPENDS cli.project_annotation_clear)

add_test(NAME cli.project_annotation_missing_image
         COMMAND donkey-cli project rename ${DONKEY_CLI_ANN_DB} 99 0x400100 nope)
set_tests_properties(cli.project_annotation_missing_image PROPERTIES
  WILL_FAIL TRUE DEPENDS cli.project_annotation_save)

add_test(NAME cli.project_annotations_reject_bad_id
         COMMAND donkey-cli project annotations ${DONKEY_CLI_ANN_DB} not-a-number)
set_tests_properties(cli.project_annotations_reject_bad_id PROPERTIES WILL_FAIL TRUE)

# ---------------------------------------------------------------------------
# Project backup and restore.
# ---------------------------------------------------------------------------

set(DONKEY_CLI_BACKUP_DB "${CMAKE_CURRENT_BINARY_DIR}/cli-project-backup.db")

add_test(NAME cli.project_backup_save
         COMMAND donkey-cli project save ${DONKEY_CLI_ANN_DB}
                 ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --json)
set_tests_properties(cli.project_backup_save PROPERTIES
  PASS_REGULAR_EXPRESSION "\"schema\": 3"
  DEPENDS cli.project_annotations_after_clear)

add_test(NAME cli.project_backup_json
         COMMAND donkey-cli project backup ${DONKEY_CLI_ANN_DB} ${DONKEY_CLI_BACKUP_DB} --force
                 --json)
set_tests_properties(cli.project_backup_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"backup\":.*\"project_schema\": 3.*\"integrity\": true"
  DEPENDS cli.project_backup_save)

add_test(NAME cli.project_backup_refuses_overwrite
         COMMAND donkey-cli project backup ${DONKEY_CLI_ANN_DB} ${DONKEY_CLI_BACKUP_DB})
set_tests_properties(cli.project_backup_refuses_overwrite PROPERTIES
  WILL_FAIL TRUE DEPENDS cli.project_backup_json)

add_test(NAME cli.project_backup_force
         COMMAND donkey-cli project backup ${DONKEY_CLI_ANN_DB} ${DONKEY_CLI_BACKUP_DB} --force --json)
set_tests_properties(cli.project_backup_force PROPERTIES
  PASS_REGULAR_EXPRESSION "\"integrity\": true"
  DEPENDS cli.project_backup_json)

add_test(NAME cli.project_restore_json
         COMMAND donkey-cli project restore ${DONKEY_CLI_BACKUP_DB} ${DONKEY_CLI_BACKUP_DB} --json)
set_tests_properties(cli.project_restore_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"project_schema\": 3.*\"integrity\": true.*\"images\": 1"
  DEPENDS cli.project_backup_force)

add_test(NAME cli.project_restore_rejects_non_database
         COMMAND donkey-cli project restore ${DONKEY_CLI_BACKUP_DB}
                 ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64)
set_tests_properties(cli.project_restore_rejects_non_database PROPERTIES
  WILL_FAIL TRUE DEPENDS cli.project_restore_json)

# ---------------------------------------------------------------------------
# Debugger CLI
# ---------------------------------------------------------------------------

add_test(NAME cli.debug_launch_mock_json
         COMMAND donkey-cli debug launch ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --mock --json)
set_tests_properties(cli.debug_launch_mock_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"state\": \"Stopped\".*\"stop_reason\": \"Entrypoint\".*\"frames\":")

add_test(NAME cli.debug_launch_human
         COMMAND donkey-cli debug launch ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --mock)
set_tests_properties(cli.debug_launch_human PROPERTIES
  PASS_REGULAR_EXPRESSION "Debugger session state: Stopped.*Call stack:")

add_test(NAME cli.debug_rejects_unknown_subcommand
         COMMAND donkey-cli debug invalid-cmd)
set_tests_properties(cli.debug_rejects_unknown_subcommand PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli.debug_rejects_missing_file
         COMMAND donkey-cli debug launch)
set_tests_properties(cli.debug_rejects_missing_file PROPERTIES WILL_FAIL TRUE)

# ---------------------------------------------------------------------------
# Patch CLI
# ---------------------------------------------------------------------------

set(DONKEY_CLI_PATCH_OUT "${CMAKE_CURRENT_BINARY_DIR}/cli_test_patched_arm64")

add_test(NAME cli.patch_apply_json
         COMMAND donkey-cli patch apply ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-macho-arm64
                 --offset 0 --replacement deadbeef --output ${DONKEY_CLI_PATCH_OUT} --json)
set_tests_properties(cli.patch_apply_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"status\": \"ok\".*\"destination\": \".*cli_test_patched_arm64\".*\"bytes_written\":")

add_test(NAME cli.patch_refuses_overwrite_without_force
         COMMAND donkey-cli patch apply ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-macho-arm64
                 --offset 0 --replacement deadbeef --output ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-macho-arm64)
set_tests_properties(cli.patch_refuses_overwrite_without_force PROPERTIES WILL_FAIL TRUE)

# ---------------------------------------------------------------------------
# Plugin CLI
# ---------------------------------------------------------------------------

add_test(NAME cli.plugin_info_json
         COMMAND donkey-cli plugin info $<TARGET_FILE:test_plugin_valid> --json)
set_tests_properties(cli.plugin_info_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"id\": \"org.donkey.test.valid\".*\"abi_version\": \\{\"major\": 1, \"minor\": 0\\}")

if(NOT WIN32)
  add_test(NAME cli.plugin_run_isolated_json
           COMMAND donkey-cli plugin run $<TARGET_FILE:test_plugin_valid> --isolate --json)
  set_tests_properties(cli.plugin_run_isolated_json PROPERTIES
    PASS_REGULAR_EXPRESSION "\"success\": true.*status.*ok")

  add_test(NAME cli.plugin_info_catches_ctor_crash
           COMMAND donkey-cli plugin info $<TARGET_FILE:test_plugin_ctor_crash>)
  set_tests_properties(cli.plugin_info_catches_ctor_crash PROPERTIES WILL_FAIL TRUE)

  add_test(NAME cli.plugin_run_isolated_catches_crash
           COMMAND donkey-cli plugin run $<TARGET_FILE:test_plugin_crash> --isolate --json)
  set_tests_properties(cli.plugin_run_isolated_catches_crash PROPERTIES
    PASS_REGULAR_EXPRESSION "\"success\": false.*\"error_code\": \"plugin.crashed\"")

  add_test(NAME cli.plugin_run_isolated_non_terminated
           COMMAND donkey-cli plugin run $<TARGET_FILE:test_plugin_non_terminated> --isolate --json)
  set_tests_properties(cli.plugin_run_isolated_non_terminated PROPERTIES
    PASS_REGULAR_EXPRESSION "\"success\": true")
endif()

add_test(NAME cli.plugin_rejects_bad_abi
         COMMAND donkey-cli plugin info $<TARGET_FILE:test_plugin_bad_abi>)
set_tests_properties(cli.plugin_rejects_bad_abi PROPERTIES WILL_FAIL TRUE)
