cmake_minimum_required(VERSION 3.25)

project(donkey VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

option(DONKEY_BUILD_UI "Build the SDL3 + Dear ImGui desktop shell" OFF)
option(DONKEY_BUILD_TESTS "Build the test suite" ON)
option(DONKEY_WARNINGS_AS_ERRORS "Treat project warnings as errors" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(DonkeyWarnings)
include(DonkeyDependencies)

# ---------------------------------------------------------------------------
# Core libraries. Every target below must build and test without SDL, ImGui,
# a display server or a GPU.
# ---------------------------------------------------------------------------

add_library(donkey_foundation STATIC
  src/foundation/diagnostics.cpp
  src/foundation/version.cpp
)
add_library(donkey::foundation ALIAS donkey_foundation)
target_include_directories(donkey_foundation
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_features(donkey_foundation PUBLIC cxx_std_20)
target_compile_definitions(donkey_foundation PRIVATE DONKEY_VERSION="${PROJECT_VERSION}")
donkey_apply_warnings(donkey_foundation)

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------

add_subdirectory(apps/donkey-cli)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(DONKEY_BUILD_TESTS)
  include(CTest)
  enable_testing()
  add_subdirectory(tests)
endif()
