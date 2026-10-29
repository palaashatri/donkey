# Pinned third-party dependencies.
#
# Canonical approach: CMake FetchContent with immutable commit SHAs. vcpkg is
# deliberately not used as well. Every dependency added here must also be
# recorded in THIRD_PARTY_NOTICES with its licence.

include(FetchContent)

set(FETCHCONTENT_QUIET OFF)

if(DONKEY_BUILD_TESTS)
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        52eb8108c5bdec04579160ae17225d66034bd723 # v1.17.0
    GIT_SHALLOW    FALSE
  )
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()
