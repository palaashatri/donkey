include(GoogleTest)

add_executable(donkey_unit_tests
  unit/binary_test.cpp
  unit/decode_test.cpp
  unit/foundation_test.cpp
)
target_link_libraries(donkey_unit_tests PRIVATE donkey::analysis GTest::gtest_main)
target_compile_definitions(donkey_unit_tests PRIVATE
  DONKEY_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)
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

add_test(NAME cli.info_pe_human
         COMMAND donkey-cli info ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-pe-x86_64.exe)
set_tests_properties(cli.info_pe_human PROPERTIES
  PASS_REGULAR_EXPRESSION "ExitProcess")

add_test(NAME cli.info_macho_json
         COMMAND donkey-cli info ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/binaries/tiny-macho-arm64 --json)
set_tests_properties(cli.info_macho_json PROPERTIES
  PASS_REGULAR_EXPRESSION "\"architecture\": \"aarch64\"")

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
