add_executable(donkey
  main.cpp
)
target_link_libraries(donkey PRIVATE donkey::ui)
donkey_apply_warnings(donkey)

if(WIN32)
  # A GUI-subsystem executable (no console window) that still uses main().
  set(DONKEY_RC_NAME donkey)
  set(DONKEY_RC_DESCRIPTION "Donkey binary workbench")
  set(DONKEY_ICON_ICO "${PROJECT_SOURCE_DIR}/assets/brand/icon.ico")
  file(TO_NATIVE_PATH "${DONKEY_ICON_ICO}" DONKEY_ICON_ICO)
  string(REPLACE "\\" "\\\\" DONKEY_ICON_ICO "${DONKEY_ICON_ICO}")
  configure_file(${PROJECT_SOURCE_DIR}/packaging/windows/donkey.rc.in
                 ${CMAKE_CURRENT_BINARY_DIR}/donkey.rc @ONLY)
  target_sources(donkey PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/donkey.rc)
  set_target_properties(donkey PROPERTIES WIN32_EXECUTABLE ON)
  if(MSVC)
    target_link_options(donkey PRIVATE /ENTRY:mainCRTStartup)
  endif()
elseif(APPLE)
  set(DONKEY_ICNS "${PROJECT_SOURCE_DIR}/assets/brand/icon.icns")
  target_sources(donkey PRIVATE ${DONKEY_ICNS})
  set_source_files_properties(${DONKEY_ICNS} PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
  set_target_properties(donkey PROPERTIES
    OUTPUT_NAME Donkey
    MACOSX_BUNDLE ON
    MACOSX_BUNDLE_INFO_PLIST ${PROJECT_SOURCE_DIR}/packaging/macos/Info.plist.in
    MACOSX_BUNDLE_BUNDLE_NAME Donkey
    MACOSX_BUNDLE_EXECUTABLE_NAME Donkey
    MACOSX_BUNDLE_GUI_IDENTIFIER io.github.palaashatri.donkey
    MACOSX_BUNDLE_ICON_FILE icon.icns
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_COPYRIGHT "MIT License, Donkey contributors"
  )
endif()
