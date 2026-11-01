# CPack pre-build script (CPACK_PRE_BUILD_SCRIPTS): sign Donkey.app in the
# staging directory after CPack has stripped its executables. Stripping
# invalidates the linker's ad-hoc signature, and an arm64 executable with a
# broken signature is killed at launch.
#
# DONKEY_CODESIGN_IDENTITY (environment) selects a Developer ID identity;
# without it the bundle is ad-hoc signed ("-"), which runs locally but is
# not notarised: Gatekeeper asks the user to confirm the first launch.

set(_identity "$ENV{DONKEY_CODESIGN_IDENTITY}")
if(_identity STREQUAL "")
  set(_identity "-")
endif()

file(GLOB_RECURSE _bundles LIST_DIRECTORIES true "${CPACK_TEMPORARY_INSTALL_DIRECTORY}/*.app")
foreach(_bundle IN LISTS _bundles)
  if(NOT IS_DIRECTORY "${_bundle}" OR NOT _bundle MATCHES "\\.app$")
    continue()
  endif()
  set(_options --force --timestamp=none --sign "${_identity}")
  if(NOT _identity STREQUAL "-")
    list(APPEND _options --options runtime --timestamp)
    list(REMOVE_ITEM _options --timestamp=none)
  endif()
  # Sign the nested CLI first, then the bundle (its main executable last).
  file(GLOB _helpers "${_bundle}/Contents/MacOS/*")
  foreach(_helper IN LISTS _helpers)
    get_filename_component(_name "${_helper}" NAME)
    if(NOT _name STREQUAL "Donkey")
      execute_process(COMMAND codesign ${_options} "${_helper}" RESULT_VARIABLE _rc)
      if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "codesign failed for ${_helper}")
      endif()
    endif()
  endforeach()
  execute_process(COMMAND codesign ${_options} "${_bundle}" RESULT_VARIABLE _rc)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "codesign failed for ${_bundle}")
  endif()
  execute_process(COMMAND codesign --verify --deep --strict "${_bundle}" RESULT_VARIABLE _rc)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "codesign verification failed for ${_bundle}")
  endif()
  message(STATUS "Signed ${_bundle} with identity '${_identity}'")
endforeach()
