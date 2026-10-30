# Pinned SQLite amalgamation for project storage. SQLite is public domain; the
# amalgamation is compiled as its own target so project code never sees a
# system SQLite version drift. Loading extensions is disabled.
include(FetchContent)

FetchContent_Declare(sqlite_amalgamation
  URL      https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip
  URL_HASH SHA256=77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(sqlite_amalgamation)

# Archive layouts differ: some CMake versions strip the single top-level
# directory, so locate the amalgamation instead of assuming a layout.
find_file(DONKEY_SQLITE_SOURCE sqlite3.c
  PATHS
    "${sqlite_amalgamation_SOURCE_DIR}"
    "${sqlite_amalgamation_SOURCE_DIR}/sqlite-amalgamation-3460100"
  NO_DEFAULT_PATH REQUIRED
)
get_filename_component(DONKEY_SQLITE_DIR "${DONKEY_SQLITE_SOURCE}" DIRECTORY)

add_library(donkey_sqlite STATIC "${DONKEY_SQLITE_SOURCE}")
add_library(donkey::sqlite ALIAS donkey_sqlite)
target_include_directories(donkey_sqlite SYSTEM PUBLIC "${DONKEY_SQLITE_DIR}")
target_compile_definitions(donkey_sqlite PRIVATE
  SQLITE_THREADSAFE=1
  SQLITE_OMIT_LOAD_EXTENSION
  SQLITE_OMIT_DEPRECATED
  SQLITE_DQS=0
  SQLITE_DEFAULT_FOREIGN_KEYS=1
)
set_target_properties(donkey_sqlite PROPERTIES
  C_STANDARD 99
  C_STANDARD_REQUIRED ON
)
