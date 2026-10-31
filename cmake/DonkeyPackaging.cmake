# Install layout and CPack configuration for release artefacts.
#
#   Linux    DEB, RPM, TGZ        bin/donkey, bin/donkey-cli, desktop entry, icons
#   macOS    DragNDrop (DMG), ZIP Donkey.app with donkey-cli in Contents/MacOS
#   Windows  NSIS (setup .exe), ZIP  donkey.exe, donkey-cli.exe, licences
#   FreeBSD  TGZ (+ .pkg via packaging/freebsd/make-pkg.sh), Linux layout
#            under /usr/local
#
# Build with -DDONKEY_BUILD_UI=ON -DDONKEY_STATIC_RUNTIME=ON (the package-*
# presets do) and run `cpack` from the build directory.

include(GNUInstallDirs)

# SPDX 2.3 software bill of materials for this build's target.
string(TIMESTAMP DONKEY_SBOM_TIMESTAMP "%Y-%m-%dT%H:%M:%SZ" UTC)
set(DONKEY_SBOM_TARGET "${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
configure_file(${PROJECT_SOURCE_DIR}/packaging/sbom/donkey.spdx.json.in
               ${PROJECT_BINARY_DIR}/donkey.spdx.json @ONLY)

set(DONKEY_DOC_FILES
  ${PROJECT_SOURCE_DIR}/LICENSE
  ${PROJECT_SOURCE_DIR}/THIRD_PARTY_NOTICES
  ${PROJECT_SOURCE_DIR}/README.md
  ${PROJECT_SOURCE_DIR}/docs/USER_GUIDE.md
  ${PROJECT_BINARY_DIR}/donkey.spdx.json
)

if(APPLE)
  if(TARGET donkey)
    install(TARGETS donkey BUNDLE DESTINATION . COMPONENT applications)
    # The CLI ships inside the bundle so one drag installs both.
    install(TARGETS donkey-cli RUNTIME DESTINATION Donkey.app/Contents/MacOS
            COMPONENT applications)
  else()
    install(TARGETS donkey-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  endif()
  install(FILES ${DONKEY_DOC_FILES} DESTINATION . COMPONENT applications)
elseif(WIN32)
  set(DONKEY_WINDOWS_TARGETS donkey-cli)
  if(TARGET donkey)
    list(APPEND DONKEY_WINDOWS_TARGETS donkey)
  endif()
  install(TARGETS ${DONKEY_WINDOWS_TARGETS} RUNTIME DESTINATION . COMPONENT applications)
  install(FILES ${DONKEY_DOC_FILES} DESTINATION . COMPONENT applications)
else()
  set(DONKEY_UNIX_TARGETS donkey-cli)
  if(TARGET donkey)
    list(APPEND DONKEY_UNIX_TARGETS donkey)
    install(FILES ${PROJECT_SOURCE_DIR}/packaging/linux/donkey.desktop
            DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
    foreach(size 16 24 32 48 64 128 256 512)
      install(FILES ${PROJECT_SOURCE_DIR}/assets/brand/icon-${size}.png
              DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/${size}x${size}/apps
              RENAME donkey.png)
    endforeach()
  endif()
  install(TARGETS ${DONKEY_UNIX_TARGETS} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  install(FILES ${DONKEY_DOC_FILES} DESTINATION ${CMAKE_INSTALL_DOCDIR})
endif()

# ---------------------------------------------------------------------------
# CPack
# ---------------------------------------------------------------------------

set(CPACK_PACKAGE_NAME "donkey")
set(CPACK_PACKAGE_VENDOR "Donkey contributors")
set(CPACK_PACKAGE_CONTACT "Donkey maintainers <https://github.com/palaashatri/donkey/issues>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Native binary reverse-engineering workbench: disassembler, decompiler, patcher, debugger")
string(CONCAT CPACK_PACKAGE_DESCRIPTION
    "Donkey opens ELF, PE and Mach-O binaries, disassembles x86, x86-64 and AArch64 with "
    "Capstone, builds control-flow graphs, decompiles a verified IR subset, stores "
    "annotations in SQLite projects, patches bytes safely and debugs native processes "
    "(Linux and Windows). Alpha software.")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/palaashatri/donkey")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_INSTALL_DIRECTORY "Donkey")
set(CPACK_RESOURCE_FILE_LICENSE ${PROJECT_SOURCE_DIR}/LICENSE)
set(CPACK_STRIP_FILES ON)
set(CPACK_PACKAGE_CHECKSUM SHA256)

string(TOLOWER "${CMAKE_SYSTEM_NAME}" _donkey_os)
if(APPLE)
  set(_donkey_os macos)
  if(CMAKE_OSX_ARCHITECTURES MATCHES ";")
    set(_donkey_arch universal)
  elseif(CMAKE_OSX_ARCHITECTURES)
    set(_donkey_arch ${CMAKE_OSX_ARCHITECTURES})
  else()
    set(_donkey_arch ${CMAKE_SYSTEM_PROCESSOR})
  endif()
else()
  set(_donkey_arch ${CMAKE_SYSTEM_PROCESSOR})
endif()
# One spelling per architecture in file names, whatever the OS calls it.
string(TOLOWER "${_donkey_arch}" _donkey_arch)
if(_donkey_arch MATCHES "^(amd64|x64|x86_64)$")
  set(_donkey_arch x86_64)
elseif(_donkey_arch MATCHES "^(aarch64|arm64)$")
  set(_donkey_arch arm64)
endif()
set(CPACK_PACKAGE_FILE_NAME "donkey-${PROJECT_VERSION}-${_donkey_os}-${_donkey_arch}")

if(APPLE)
  set(CPACK_GENERATOR "DragNDrop;ZIP")
  set(CPACK_DMG_VOLUME_NAME "Donkey ${PROJECT_VERSION}")
  set(CPACK_DMG_FORMAT UDZO)
  # The licence is in the image as a file; the deprecated SLA resource
  # tooling is not available on current macOS.
  set(CPACK_DMG_SLA_USE_RESOURCE_FILE_LICENSE OFF)
  set(CPACK_PRE_BUILD_SCRIPTS ${PROJECT_SOURCE_DIR}/packaging/macos/sign-bundle.cmake)
elseif(WIN32)
  set(CPACK_GENERATOR "NSIS;ZIP")
  set(CPACK_NSIS_PACKAGE_NAME "Donkey ${PROJECT_VERSION}")
  set(CPACK_NSIS_DISPLAY_NAME "Donkey")
  set(CPACK_NSIS_MUI_ICON ${PROJECT_SOURCE_DIR}/assets/brand/icon.ico)
  set(CPACK_NSIS_MUI_UNIICON ${PROJECT_SOURCE_DIR}/assets/brand/icon.ico)
  set(CPACK_NSIS_INSTALLED_ICON_NAME donkey.exe)
  set(CPACK_NSIS_URL_INFO_ABOUT ${CPACK_PACKAGE_HOMEPAGE_URL})
  set(CPACK_NSIS_HELP_LINK ${CPACK_PACKAGE_HOMEPAGE_URL})
  set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
  # Offers to put donkey-cli on PATH.
  set(CPACK_NSIS_MODIFY_PATH ON)
  set(CPACK_NSIS_EXECUTABLES_DIRECTORY .)
  set(CPACK_PACKAGE_EXECUTABLES "donkey;Donkey")
  set(CPACK_CREATE_DESKTOP_LINKS donkey)
  set(CPACK_NSIS_MANIFEST_DPI_AWARE ON)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  # The .pkg is built by packaging/freebsd/make-pkg.sh with pkg(8); CPack's
  # FREEBSD generator needs a CMake built against libpkg.
  set(CPACK_GENERATOR "TGZ")
  set(CPACK_PACKAGING_INSTALL_PREFIX "/usr/local")
else()
  set(CPACK_GENERATOR "DEB;RPM;TGZ")
  set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
  # Debian
  set(CPACK_DEBIAN_PACKAGE_SECTION devel)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  # SDL loads the windowing system and Vulkan at run time (dlopen), so they
  # are recommendations rather than hard dependencies.
  set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "libvulkan1, mesa-vulkan-drivers | vulkan-icd, libx11-6, libxkbcommon0, libwayland-client0")
  set(CPACK_DEBIAN_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}.deb")
  # RPM
  set(CPACK_RPM_PACKAGE_LICENSE "MIT")
  set(CPACK_RPM_PACKAGE_GROUP "Development/Tools")
  set(CPACK_RPM_PACKAGE_URL ${CPACK_PACKAGE_HOMEPAGE_URL})
  set(CPACK_RPM_PACKAGE_AUTOREQ ON)
  set(CPACK_RPM_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}.rpm")
  set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
      /usr/share/applications
      /usr/share/icons
      /usr/share/icons/hicolor
      /usr/share/doc)
  foreach(size 16 24 32 48 64 128 256 512)
    list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
         /usr/share/icons/hicolor/${size}x${size}
         /usr/share/icons/hicolor/${size}x${size}/apps)
  endforeach()
endif()

configure_file(${PROJECT_SOURCE_DIR}/packaging/cpack-options.cmake.in
               ${PROJECT_BINARY_DIR}/CPackOptions.cmake @ONLY)
set(CPACK_PROJECT_CONFIG_FILE ${PROJECT_BINARY_DIR}/CPackOptions.cmake)

include(CPack)
