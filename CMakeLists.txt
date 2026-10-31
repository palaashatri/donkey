cmake_minimum_required(VERSION 3.25)

project(donkey VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

option(DONKEY_BUILD_UI "Build the SDL3 + Dear ImGui desktop shell" OFF)
option(DONKEY_UI_SMOKE_TEST "Register display-dependent UI smoke tests" OFF)
option(DONKEY_BUILD_TESTS "Build the test suite" ON)
option(DONKEY_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
option(DONKEY_WARNINGS_AS_ERRORS "Treat project warnings as errors" OFF)
option(DONKEY_STATIC_RUNTIME
       "Link the C/C++ runtime statically (self-contained release executables)" OFF)

if(DONKEY_STATIC_RUNTIME)
  if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  elseif(MINGW)
    # Fully static: no libstdc++, libgcc or libwinpthread DLLs to ship.
    add_link_options(-static)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # glibc stays dynamic (it cannot be linked statically in a portable way);
    # libstdc++ and libgcc travel with the executable.
    add_link_options(-static-libstdc++ -static-libgcc)
  endif()
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(DonkeyWarnings)
include(DonkeyDependencies)
include(DonkeyStorageDependencies)

# ---------------------------------------------------------------------------
# Core libraries. Every target below must build and test without SDL, ImGui,
# a display server or a GPU.
# ---------------------------------------------------------------------------

add_library(donkey_foundation STATIC
  src/foundation/diagnostics.cpp
  src/foundation/scheduler.cpp
  src/foundation/thread_priority.cpp
  src/foundation/sha256.cpp
  src/foundation/version.cpp
)
add_library(donkey::foundation ALIAS donkey_foundation)
target_include_directories(donkey_foundation
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_features(donkey_foundation PUBLIC cxx_std_20)
# Workers, SQLite's sorter threads and std::thread users need the platform
# thread library (a separate libpthread on FreeBSD and older glibc).
find_package(Threads REQUIRED)
target_link_libraries(donkey_foundation PUBLIC Threads::Threads)
target_compile_definitions(donkey_foundation PRIVATE DONKEY_VERSION="${PROJECT_VERSION}")
donkey_apply_warnings(donkey_foundation)

add_library(donkey_binary STATIC
  src/binary/byte_buffer.cpp
  src/binary/byte_reader.cpp
  src/binary/dwarf.cpp
  src/binary/elf.cpp
  src/binary/image.cpp
  src/binary/isolation.cpp
  src/binary/macho.cpp
  src/binary/pe.cpp
)
add_library(donkey::binary ALIAS donkey_binary)
target_include_directories(donkey_binary
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(donkey_binary PUBLIC donkey::foundation)
target_compile_features(donkey_binary PUBLIC cxx_std_20)
donkey_apply_warnings(donkey_binary)

add_library(donkey_decode STATIC
  src/decode/decode.cpp
)
add_library(donkey::decode ALIAS donkey_decode)
target_include_directories(donkey_decode
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(donkey_decode PUBLIC donkey::binary PRIVATE capstone_static)
target_compile_features(donkey_decode PUBLIC cxx_std_20)
donkey_apply_warnings(donkey_decode)

add_library(donkey_analysis STATIC
  src/analysis/analysis.cpp
  src/analysis/cfg.cpp
  src/analysis/graph_layout.cpp
)
add_library(donkey::analysis ALIAS donkey_analysis)
target_include_directories(donkey_analysis
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(donkey_analysis PUBLIC donkey::decode)
target_compile_features(donkey_analysis PUBLIC cxx_std_20)
donkey_apply_warnings(donkey_analysis)

add_library(donkey_ir STATIC
  src/ir/abi.cpp
  src/ir/ir.cpp
  src/ir/lift.cpp
  src/ir/lift_aarch64.cpp
  src/ir/structure.cpp
)
add_library(donkey::ir ALIAS donkey_ir)
target_include_directories(donkey_ir
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(donkey_ir PUBLIC donkey::analysis)
target_compile_features(donkey_ir PUBLIC cxx_std_20)
donkey_apply_warnings(donkey_ir)

add_library(donkey_project STATIC
  src/project/project.cpp
)
add_library(donkey::project ALIAS donkey_project)
target_include_directories(donkey_project
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(donkey_project
  PUBLIC donkey::analysis donkey::sqlite
)
target_compile_features(donkey_project PUBLIC cxx_std_20)
donkey_apply_warnings(donkey_project)

add_library(donkey_debug STATIC
  src/debug/controller.cpp
  src/debug/debug.cpp
  src/debug/mock_adapter.cpp
  src/debug/native_linux.cpp
  src/debug/native_unsupported.cpp
  src/debug/native_windows.cpp
)
add_library(donkey::debug ALIAS donkey_debug)
target_include_directories(donkey_debug
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/debug>
)
target_link_libraries(donkey_debug PUBLIC donkey::foundation donkey::analysis)
if(WIN32)
  target_link_libraries(donkey_debug PRIVATE dbghelp psapi)
endif()
target_compile_features(donkey_debug PUBLIC cxx_std_20)
donkey_apply_warnings(donkey_debug)

add_library(donkey_patch STATIC
  src/patch/patch.cpp
)
add_library(donkey::patch ALIAS donkey_patch)
target_include_directories(donkey_patch
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(donkey_patch PUBLIC donkey::binary donkey::foundation)
target_compile_features(donkey_patch PUBLIC cxx_std_20)
donkey_apply_warnings(donkey_patch)

add_library(donkey_plugin STATIC
  src/plugin/plugin.cpp
  src/plugin/isolated_host.cpp
)
add_library(donkey::plugin ALIAS donkey_plugin)
target_include_directories(donkey_plugin
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(donkey_plugin PUBLIC donkey::foundation ${CMAKE_DL_LIBS})
target_compile_features(donkey_plugin PUBLIC cxx_std_20)
donkey_apply_warnings(donkey_plugin)

# The session owns loading, analysis and project persistence on a worker
# thread. It has no SDL or ImGui dependency, so it is built headless and is
# covered by the unit tests even when the desktop shell is disabled.
add_library(donkey_session STATIC
  src/ui/session.cpp
)
add_library(donkey::session ALIAS donkey_session)
target_include_directories(donkey_session
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/ui>
)
target_link_libraries(donkey_session PUBLIC donkey::analysis donkey::project)
target_compile_features(donkey_session PUBLIC cxx_std_20)
donkey_apply_warnings(donkey_session)

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------

add_subdirectory(apps/donkey-cli)

# ---------------------------------------------------------------------------
# Desktop shell (SDL3 + Dear ImGui). Never a dependency of the core targets.
# ---------------------------------------------------------------------------

if(DONKEY_BUILD_UI)
  include(DonkeyUiDependencies)

  add_library(donkey_ui STATIC
    src/ui/application.cpp
    src/ui/components.cpp
    src/ui/debugger_view.cpp
    src/ui/decompiler_view.cpp
    src/ui/disasm_view.cpp
    src/ui/gallery_view.cpp
    src/ui/graph_view.cpp
    src/ui/hex_view.cpp
    src/ui/panels_view.cpp
    src/ui/theme.cpp
    src/ui/ui_test.cpp
    src/ui/workspace.cpp
  )
  add_library(donkey::ui ALIAS donkey_ui)
  target_include_directories(donkey_ui
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  )
  target_link_libraries(donkey_ui
    PUBLIC donkey::analysis donkey::session
    PUBLIC donkey::patch
    PRIVATE donkey::ir donkey::project donkey::debug donkey_imgui
  )
  target_compile_features(donkey_ui PUBLIC cxx_std_20)
  donkey_apply_warnings(donkey_ui)

  add_subdirectory(apps/donkey)
endif()

# ---------------------------------------------------------------------------
# Fuzzers. Clang-only, sanitizer-backed, never part of the default build.
# ---------------------------------------------------------------------------

if(DONKEY_BUILD_FUZZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "DONKEY_BUILD_FUZZERS requires Clang (libFuzzer)")
  endif()
  set(DONKEY_FUZZ_SANITIZE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)
  add_executable(fuzz_binary fuzz/fuzz_binary.cpp)
  target_link_libraries(fuzz_binary PRIVATE donkey::ir)
  target_compile_features(fuzz_binary PRIVATE cxx_std_20)
  target_compile_options(fuzz_binary PRIVATE ${DONKEY_FUZZ_SANITIZE})
  target_link_options(fuzz_binary PRIVATE ${DONKEY_FUZZ_SANITIZE})

  add_executable(fuzz_ir fuzz/fuzz_ir.cpp)
  target_link_libraries(fuzz_ir PRIVATE donkey::ir)
  target_compile_features(fuzz_ir PRIVATE cxx_std_20)
  target_compile_options(fuzz_ir PRIVATE ${DONKEY_FUZZ_SANITIZE})
  target_link_options(fuzz_ir PRIVATE ${DONKEY_FUZZ_SANITIZE})
endif()

# ---------------------------------------------------------------------------
# Install rules and release packaging (CPack)
# ---------------------------------------------------------------------------

include(DonkeyDependencyGraph)
include(DonkeyPackaging)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(DONKEY_BUILD_TESTS)
  include(CTest)
  enable_testing()
  add_subdirectory(tests)
endif()
