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

set_target_properties(
  test_plugin_valid
  test_plugin_bad_abi
  test_plugin_crash
  test_plugin_hang
  test_plugin_ctor_crash
  test_plugin_non_terminated
  PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON
)

# Native debugger target. Built unoptimised with frame pointers so the call
# stack and step-out tests have a frame chain to follow.
# It is compiled with -g: its DWARF is the debug-info fixture (ELF, and PE
# with MinGW; Apple keeps DWARF out of the executable).
add_executable(donkey_test_debuggee fixtures/debuggee/debuggee.c)
# Demo program for the documentation screenshots.
add_executable(donkey_demo fixtures/demo/demo.c)
if(NOT MSVC)
  target_compile_options(donkey_demo PRIVATE -O1 -g -fno-inline-functions)
endif()
# The dynamic-module fixture `debuggee load` opens at run time.
add_library(donkey_test_module SHARED fixtures/debuggee/module.c)
if(MSVC)
  target_compile_options(donkey_test_debuggee PRIVATE /Od /Oy-)
  target_compile_options(donkey_test_module PRIVATE /Od /Oy-)
else()
  target_compile_options(donkey_test_debuggee PRIVATE -O0 -g -fno-omit-frame-pointer)
  target_compile_options(donkey_test_module PRIVATE -O0 -g -fno-omit-frame-pointer)
endif()
target_link_libraries(donkey_test_debuggee PRIVATE ${CMAKE_DL_LIBS})

# Decompiler differential corpus (M8): the same source at three
# optimisation levels, built with the host C compiler.
set(DONKEY_CORPUS_LIBRARIES)
foreach(level O0 O2 O3)
  add_library(donkey_corpus_${level} SHARED corpus/corpus.c)
  if(NOT MSVC)
    target_compile_options(donkey_corpus_${level} PRIVATE -${level} -fno-stack-protector)
  endif()
  list(APPEND DONKEY_CORPUS_LIBRARIES donkey_corpus_${level})
endforeach()

add_executable(donkey_unit_tests
  unit/acceptance_test.cpp
  unit/decompiler_corpus_test.cpp
  unit/binary_test.cpp
  unit/cfg_test.cpp
  unit/debug_info_test.cpp
  unit/debug_test.cpp
  unit/decode_test.cpp
  unit/foundation_test.cpp
  unit/graph_layout_test.cpp
  unit/ir_test.cpp
  unit/large_file_test.cpp
  unit/native_debug_test.cpp
  unit/patch_test.cpp
  unit/plugin_test.cpp
  unit/project_test.cpp
  unit/scheduler_test.cpp
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
  DONKEY_TEST_DEBUGGEE_PATH="$<TARGET_FILE:donkey_test_debuggee>"
  DONKEY_TEST_MODULE_PATH="$<TARGET_FILE:donkey_test_module>"
  DONKEY_CORPUS_O0_PATH="$<TARGET_FILE:donkey_corpus_O0>"
  DONKEY_CORPUS_O2_PATH="$<TARGET_FILE:donkey_corpus_O2>"
  DONKEY_CORPUS_O3_PATH="$<TARGET_FILE:donkey_corpus_O3>"
  DONKEY_CORPUS_REPORT="${CMAKE_CURRENT_BINARY_DIR}/decompiler-corpus-report.json"
  DONKEY_CORPUS_COMPILER="${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION} ${CMAKE_SYSTEM_PROCESSOR}"
)
add_dependencies(donkey_unit_tests donkey_demo donkey_test_debuggee donkey_test_module ${DONKEY_CORPUS_LIBRARIES} test_plugin_valid test_plugin_bad_abi test_plugin_crash test_plugin_hang test_plugin_ctor_crash test_plugin_non_terminated)
donkey_apply_warnings(donkey_unit_tests)

gtest_discover_tests(donkey_unit_tests DISCOVERY_TIMEOUT 30)
if(WIN32)
  target_link_libraries(donkey_unit_tests PRIVATE psapi)
endif()

# 1 GiB memory-budget test (M10/A24). Release builds only: hashing and
# scanning a gigabyte takes tens of seconds unoptimised.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_executable(donkey_large_tests unit/large_file_test.cpp)
  target_link_libraries(donkey_large_tests PRIVATE donkey::analysis GTest::gtest_main)
  if(WIN32)
    target_link_libraries(donkey_large_tests PRIVATE psapi)
  endif()
  target_compile_definitions(donkey_large_tests PRIVATE
    DONKEY_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
    DONKEY_LARGE_FILE_TESTS=1)
  donkey_apply_warnings(donkey_large_tests)
  add_test(NAME large.load_and_analyse_1gib
           COMMAND donkey_large_tests --gtest_filter=LargeFile.Mapped1GiB*)
  set_tests_properties(large.load_and_analyse_1gib PROPERTIES TIMEOUT 600 LABELS large)
endif()

add_test(NAME cli.callgraph_json
         COMMAND donkey-cli callgraph $<TARGET_FILE:donkey_test_debuggee> --json)
set_tests_properties(cli.callgraph_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"edges\": \\[.*main\".*donkey_debuggee_tick.*\"unresolved\"")

# M0: the headless core never links the desktop shell's libraries.
add_test(NAME deps.core_has_no_ui_links
  COMMAND ${CMAKE_COMMAND} -DGRAPH=${CMAKE_BINARY_DIR}/donkey-core-link-graph.txt
          -P ${PROJECT_SOURCE_DIR}/cmake/checks/check_link_graph.cmake)
add_test(NAME deps.checker_rejects_ui_link
  COMMAND ${CMAKE_COMMAND} -DGRAPH=${PROJECT_SOURCE_DIR}/tests/fixtures/manifests/bad-link-graph.txt
          -P ${PROJECT_SOURCE_DIR}/cmake/checks/check_link_graph.cmake)
set_tests_properties(deps.checker_rejects_ui_link PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli.debuginfo_json
         COMMAND donkey-cli debuginfo $<TARGET_FILE:donkey_test_module> --json)
if(APPLE OR MSVC)
  # No DWARF in the executable with these toolchains: the command says so.
  set_tests_properties(cli.debuginfo_json PROPERTIES WILL_FAIL TRUE)
else()
  set_tests_properties(cli.debuginfo_json PROPERTIES
    PASS_REGULAR_EXPRESSION "\"prototype\": \"int donkey_module_answer\\(int value\\)\".*\"provenance\": \"DWARF [2-5] @")
endif()
add_test(NAME cli.debuginfo_reports_absence
         COMMAND donkey-cli debuginfo ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64)
set_tests_properties(cli.debuginfo_reports_absence PROPERTIES WILL_FAIL TRUE)

add_test(NAME sbom.valid
  COMMAND ${CMAKE_COMMAND} -DSBOM=${PROJECT_BINARY_DIR}/donkey.spdx.json
          -P ${PROJECT_SOURCE_DIR}/cmake/checks/check_sbom.cmake)

# M12: the acceptance manifest names only registered tests and real fixtures.
set(DONKEY_ACCEPTANCE_UI OFF)
if(DONKEY_BUILD_UI AND DONKEY_UI_SMOKE_TEST)
  set(DONKEY_ACCEPTANCE_UI ON)
endif()
add_test(NAME acceptance.manifest
  COMMAND ${CMAKE_COMMAND} -DMANIFEST=${CMAKE_CURRENT_SOURCE_DIR}/acceptance/manifest.json
          -DBUILD_DIR=${PROJECT_BINARY_DIR} -DCTEST=${CMAKE_CTEST_COMMAND}
          -DUI=${DONKEY_ACCEPTANCE_UI} -DSOURCE_DIR=${PROJECT_SOURCE_DIR}
          -P ${PROJECT_SOURCE_DIR}/cmake/checks/check_acceptance.cmake)

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

if(NOT WIN32)
  add_test(NAME cli.info_isolated_json
           COMMAND donkey-cli info ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64 --isolate --json)
  set_tests_properties(cli.info_isolated_json PROPERTIES
    PASS_REGULAR_EXPRESSION "\"schema_version\": 1.*\"format\": \"ELF\"")
endif()

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
                   --exit-after-frames 20 --config-dir ${CMAKE_CURRENT_BINARY_DIR}/ui-config/smoke)
  set_tests_properties(ui.smoke_loads_elf PROPERTIES TIMEOUT 120)

  # Each format exercises different views (PE code has instruction classes
  # the ELF fixture lacks); debug builds turn ImGui misuse into assertions.
  add_test(NAME ui.smoke_loads_pe
           COMMAND donkey ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-pe-x86_64.exe
                   --exit-after-frames 20 --config-dir ${CMAKE_CURRENT_BINARY_DIR}/ui-config/smoke)
  add_test(NAME ui.smoke_loads_macho
           COMMAND donkey ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-macho-arm64
                   --exit-after-frames 20 --config-dir ${CMAKE_CURRENT_BINARY_DIR}/ui-config/smoke)
  add_test(NAME ui.smoke_software_renderer
           COMMAND donkey --renderer software
                   ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-elf-x86_64
                   --exit-after-frames 20 --config-dir ${CMAKE_CURRENT_BINARY_DIR}/ui-config/smoke)
  set_tests_properties(ui.smoke_loads_pe ui.smoke_loads_macho ui.smoke_software_renderer
                       PROPERTIES TIMEOUT 120)

  add_test(NAME ui.smoke_rejects_unknown_option COMMAND donkey --nope)
  set_tests_properties(ui.smoke_rejects_unknown_option PROPERTIES WILL_FAIL TRUE)

  # Scripted UI tests (tests/ui/*.donkeyui, docs/UI_TESTING.md): real SDL
  # input events through the real event loop, with assertions and a timing
  # report in ui-reports/. Each run gets its own layout directory.
  set(DONKEY_UI_REPORT_DIR ${CMAKE_CURRENT_BINARY_DIR}/ui-reports)
  set(DONKEY_UI_CONFIG_DIR ${CMAKE_CURRENT_BINARY_DIR}/ui-config)
  file(MAKE_DIRECTORY ${DONKEY_UI_REPORT_DIR})
  function(donkey_ui_script name)
    cmake_parse_arguments(ARG "" "CONFIG;RENDERER" "" ${ARGN})
    if(NOT ARG_CONFIG)
      set(ARG_CONFIG ${name})
    endif()
    if(NOT ARG_RENDERER)
      set(ARG_RENDERER software)
    endif()
    add_test(NAME ui.script_${name}
             COMMAND donkey --renderer ${ARG_RENDERER}
                     --config-dir ${DONKEY_UI_CONFIG_DIR}/${ARG_CONFIG}
                     --ui-script ${CMAKE_CURRENT_SOURCE_DIR}/ui/${name}.donkeyui
                     --ui-report ${DONKEY_UI_REPORT_DIR}/${name}.json
                     $<TARGET_FILE:donkey_test_debuggee>)
    set_tests_properties(ui.script_${name} PROPERTIES
      TIMEOUT 180 PASS_REGULAR_EXPRESSION "donkey ui-test: PASS"
      FAIL_REGULAR_EXPRESSION "donkey ui-test: FAIL")
  endfunction()
  donkey_ui_script(keyboard_ime)
  donkey_ui_script(gallery_keyboard)
  donkey_ui_script(virtualization)
  donkey_ui_script(display_dpi_device)
  # Device loss on the default (SDL_GPU where available) renderer too.
  add_test(NAME ui.script_display_dpi_device_auto
           COMMAND donkey --renderer auto --config-dir ${DONKEY_UI_CONFIG_DIR}/dpi-auto
                   --ui-script ${CMAKE_CURRENT_SOURCE_DIR}/ui/display_dpi_device.donkeyui
                   --ui-report ${DONKEY_UI_REPORT_DIR}/display_dpi_device_auto.json
                   $<TARGET_FILE:donkey_test_debuggee>)
  set_tests_properties(ui.script_display_dpi_device_auto PROPERTIES
    TIMEOUT 180 PASS_REGULAR_EXPRESSION "donkey ui-test: PASS"
    FAIL_REGULAR_EXPRESSION "donkey ui-test: FAIL")
  # Documentation screenshots of the demo program (BMP; see docs/UI_TESTING.md).
  add_test(NAME ui.screenshots
           COMMAND ${CMAKE_COMMAND} -E env DONKEY_SCREENSHOT_DIR=${CMAKE_CURRENT_BINARY_DIR}/screenshots
                   $<TARGET_FILE:donkey> --renderer software
                   --config-dir ${DONKEY_UI_CONFIG_DIR}/screenshots
                   --ui-script ${CMAKE_CURRENT_SOURCE_DIR}/ui/screenshots.donkeyui
                   $<TARGET_FILE:donkey_demo>)
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/screenshots)
  # Always from the default layout, never one a previous run saved.
  add_test(NAME ui.screenshots_clean
           COMMAND ${CMAKE_COMMAND} -E rm -rf ${DONKEY_UI_CONFIG_DIR}/screenshots)
  set_tests_properties(ui.screenshots_clean PROPERTIES FIXTURES_SETUP ui_screenshots_clean)
  set_tests_properties(ui.screenshots PROPERTIES FIXTURES_REQUIRED ui_screenshots_clean

    TIMEOUT 180 PASS_REGULAR_EXPRESSION "donkey ui-test: PASS"
    FAIL_REGULAR_EXPRESSION "donkey ui-test: FAIL")

  # The responsiveness run starts 8 analysis threads; keep it alone.
  donkey_ui_script(responsiveness)
  set_tests_properties(ui.script_responsiveness PROPERTIES RUN_SERIAL TRUE)

  # Layout persistence: clean directory, save a changed layout, reopen.
  add_test(NAME ui.layout_clean
           COMMAND ${CMAKE_COMMAND} -E rm -rf ${DONKEY_UI_CONFIG_DIR}/layout)
  donkey_ui_script(layout_save CONFIG layout)
  donkey_ui_script(layout_restore CONFIG layout)
  set_tests_properties(ui.layout_clean PROPERTIES FIXTURES_SETUP ui_layout_clean)
  set_tests_properties(ui.script_layout_save PROPERTIES
    FIXTURES_REQUIRED ui_layout_clean FIXTURES_SETUP ui_layout_saved)
  set_tests_properties(ui.script_layout_restore PROPERTIES FIXTURES_REQUIRED ui_layout_saved)
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
  PASS_REGULAR_EXPRESSION "\"schema\": 4.*\"integrity\": true.*\"sha256\"")

add_test(NAME cli.project_info_elf_json
         COMMAND donkey-cli project info ${DONKEY_CLI_PROJECT_DB} --json)
set_tests_properties(cli.project_info_elf_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"project_schema\": 4.*\"integrity\": true.*\"format\": \"ELF\""
  DEPENDS cli.project_save_elf_json)

if(DONKEY_BUILD_UI AND DONKEY_UI_SMOKE_TEST)
  add_test(NAME ui.smoke_loads_project
           COMMAND donkey --project ${DONKEY_CLI_PROJECT_DB} --exit-after-frames 20
                   --config-dir ${CMAKE_CURRENT_BINARY_DIR}/ui-config/smoke)
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
  PASS_REGULAR_EXPRESSION "\"schema\": 4.*\"image_id\": 1")

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
  DEPENDS "cli.project_rename;cli.project_comment;cli.project_bookmark;cli.project_annotations_json")

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
  PASS_REGULAR_EXPRESSION "\"schema\": 4"
  DEPENDS cli.project_annotations_after_clear)

add_test(NAME cli.project_backup_json
         COMMAND donkey-cli project backup ${DONKEY_CLI_ANN_DB} ${DONKEY_CLI_BACKUP_DB} --force
                 --json)
set_tests_properties(cli.project_backup_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"backup\":.*\"project_schema\": 4.*\"integrity\": true"
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
  PASS_REGULAR_EXPRESSION "\"project_schema\": 4.*\"integrity\": true.*\"images\": 1"
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
  PASS_REGULAR_EXPRESSION "Debugger .mock adapter.: stopped at Entrypoint.*Call stack:")

# Real native debugging through the CLI where the host has a backend.
if((CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|aarch64|arm64")
   OR (WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64"))
  add_test(NAME cli.debug_native_run_json
           COMMAND donkey-cli debug launch $<TARGET_FILE:donkey_test_debuggee>
                   --break donkey_debuggee_tick --run --json)
  set_tests_properties(cli.debug_native_run_json PROPERTIES
    PASS_REGULAR_EXPRESSION "\"adapter\": \"native\".*\"stop_reason\": \"Entrypoint\".*\"stops\": \\[.*\"Breakpoint\".*donkey_debuggee_tick.*\"Breakpoint\".*\"Breakpoint\".*\"exit_code\": 42")
else()
  add_test(NAME cli.debug_native_unsupported
           COMMAND donkey-cli debug launch $<TARGET_FILE:donkey_test_debuggee>)
  set_tests_properties(cli.debug_native_unsupported PROPERTIES
    PASS_REGULAR_EXPRESSION "debug\\.unsupported_platform")
endif()

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

if(NOT WIN32)
  add_test(NAME cli.plugin_info_json
           COMMAND donkey-cli plugin info $<TARGET_FILE:test_plugin_valid> --json)
  set_tests_properties(cli.plugin_info_json PROPERTIES
    PASS_REGULAR_EXPRESSION "\"id\": \"org.donkey.test.valid\".*\"abi_version\": \\{\"major\": 1, \"minor\": 0\\}")

  add_test(NAME cli.plugin_run_isolated_json
           COMMAND donkey-cli plugin run $<TARGET_FILE:test_plugin_valid> --isolate --json)
  set_tests_properties(cli.plugin_run_isolated_json PROPERTIES
    PASS_REGULAR_EXPRESSION "\"success\": true.*status.*ok")

  add_test(NAME cli.plugin_info_catches_ctor_crash
           COMMAND donkey-cli plugin info $<TARGET_FILE:test_plugin_ctor_crash>)
  set_tests_properties(cli.plugin_info_catches_ctor_crash PROPERTIES
    PASS_REGULAR_EXPRESSION "plugin\\.crashed")

  add_test(NAME cli.plugin_run_isolated_catches_crash
           COMMAND donkey-cli plugin run $<TARGET_FILE:test_plugin_crash> --isolate --json)
  set_tests_properties(cli.plugin_run_isolated_catches_crash PROPERTIES
    PASS_REGULAR_EXPRESSION "\"success\": false.*\"error_code\": \"plugin.crashed\"")

  add_test(NAME cli.plugin_run_isolated_non_terminated
           COMMAND donkey-cli plugin run $<TARGET_FILE:test_plugin_non_terminated> --isolate --json)
  set_tests_properties(cli.plugin_run_isolated_non_terminated PROPERTIES
    PASS_REGULAR_EXPRESSION "\"success\": true")

  add_test(NAME cli.plugin_rejects_bad_abi
           COMMAND donkey-cli plugin info $<TARGET_FILE:test_plugin_bad_abi>)
  set_tests_properties(cli.plugin_rejects_bad_abi PROPERTIES
    PASS_REGULAR_EXPRESSION "plugin\\.abi_version_mismatch")
else()
  add_test(NAME cli.plugin_info_fails_closed_on_windows
           COMMAND donkey-cli plugin info $<TARGET_FILE:test_plugin_ctor_crash>)
  set_tests_properties(cli.plugin_info_fails_closed_on_windows PROPERTIES
    PASS_REGULAR_EXPRESSION "plugin\\.isolation_unavailable")

  add_test(NAME cli.plugin_run_isolated_fails_closed_on_windows
           COMMAND donkey-cli plugin run $<TARGET_FILE:test_plugin_valid> --isolate --json)
  set_tests_properties(cli.plugin_run_isolated_fails_closed_on_windows PROPERTIES
    PASS_REGULAR_EXPRESSION "plugin\\.isolation_unavailable")

  add_test(NAME cli.binary_isolated_fails_closed_on_windows
           COMMAND donkey-cli info $<TARGET_FILE:test_plugin_valid> --isolate --json)
  set_tests_properties(cli.binary_isolated_fails_closed_on_windows PROPERTIES
    PASS_REGULAR_EXPRESSION "binary\\.isolation_unavailable")
endif()

add_test(NAME cli.plugin_run_trusted_non_terminated
         COMMAND donkey-cli plugin run $<TARGET_FILE:test_plugin_non_terminated> --json)
set_tests_properties(cli.plugin_run_trusted_non_terminated PROPERTIES
  PASS_REGULAR_EXPRESSION "\"success\": true")

# Every CLI project test reads or writes the same database files; CTest must
# never run two of them at once (`ctest -j`).
get_property(_donkey_all_tests DIRECTORY PROPERTY TESTS)
foreach(_donkey_test IN LISTS _donkey_all_tests)
  if(_donkey_test MATCHES "^cli\\.project_")
    set_property(TEST ${_donkey_test} APPEND PROPERTY RESOURCE_LOCK donkey_cli_project_db)
  endif()
endforeach()
