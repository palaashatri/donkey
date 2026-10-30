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

# Capstone: instruction decoding for x86/x86-64/AArch64. Stable 5.0.9 release.
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT OFF CACHE BOOL "" FORCE)
FetchContent_Declare(capstone
  GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
  GIT_TAG        022575848782a4801fd150fdbc927effcbca0864 # 5.0.9
)
FetchContent_MakeAvailable(capstone)
