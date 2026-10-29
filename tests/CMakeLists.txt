include(GoogleTest)

add_executable(donkey_unit_tests
  unit/binary_test.cpp
  unit/foundation_test.cpp
)
target_link_libraries(donkey_unit_tests PRIVATE donkey::binary GTest::gtest_main)
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
