add_executable(donkey-cli
  commands.cpp
  main.cpp
)
target_link_libraries(donkey-cli PRIVATE donkey::project donkey::ir donkey::debug donkey::patch donkey::plugin)
donkey_apply_warnings(donkey-cli)

if(WIN32)
  set(DONKEY_RC_NAME donkey-cli)
  set(DONKEY_RC_DESCRIPTION "Donkey command-line workbench")
  set(DONKEY_ICON_ICO "${PROJECT_SOURCE_DIR}/assets/brand/icon.ico")
  file(TO_NATIVE_PATH "${DONKEY_ICON_ICO}" DONKEY_ICON_ICO)
  string(REPLACE "\\" "\\\\" DONKEY_ICON_ICO "${DONKEY_ICON_ICO}")
  configure_file(${PROJECT_SOURCE_DIR}/packaging/windows/donkey.rc.in
                 ${CMAKE_CURRENT_BINARY_DIR}/donkey-cli.rc @ONLY)
  target_sources(donkey-cli PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/donkey-cli.rc)
endif()
