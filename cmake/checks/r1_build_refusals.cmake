# G20-T1: tools/r1/build.cmake refuses what it must refuse, without the network. Each case writes a
# manifest whose source is a local archive (a file:// URL) and runs the fetch step, which must fail
# with the expected message. A last case checks that a good archive is fetched and unpacked.
# Inputs: R1_SCRIPT (tools/r1/build.cmake), WORK (a scratch directory).

if(NOT DEFINED R1_SCRIPT OR NOT DEFINED WORK)
  message(FATAL_ERROR "r1_build_refusals: R1_SCRIPT and WORK are required")
endif()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/payload/pkg-1" "${WORK}/payload/other")
file(WRITE "${WORK}/payload/escape.txt" "outside\n")
file(WRITE "${WORK}/payload/pkg-1/a.c" "int a(void) { return 1; }\n")
file(WRITE "${WORK}/payload/other/b.c" "int b(void) { return 2; }\n")

# good.tar: everything under pkg-1/. dotdot.tar: a member that climbs out of pkg-1/. outside.tar: a
# member beside pkg-1/ instead of in it.
execute_process(COMMAND ${CMAKE_COMMAND} -E tar cf ../good.tar pkg-1/a.c
                WORKING_DIRECTORY "${WORK}/payload" COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND ${CMAKE_COMMAND} -E tar cf ../dotdot.tar pkg-1/a.c pkg-1/../escape.txt
                WORKING_DIRECTORY "${WORK}/payload" COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND ${CMAKE_COMMAND} -E tar cf ../outside.tar pkg-1/a.c other/b.c
                WORKING_DIRECTORY "${WORK}/payload" COMMAND_ERROR_IS_FATAL ANY)
file(SHA256 "${WORK}/good.tar" good_sha)
file(SHA256 "${WORK}/dotdot.tar" dotdot_sha)
file(SHA256 "${WORK}/outside.tar" outside_sha)

set(toolchains [=["toolchains": {"t": {"cc": "cc", "strip": "strip", "strip_package": "binutils", "package": "gcc"}}]=])
set(build [=["builds": [{"name": "a", "source": "pkg", "kind": "shared", "files": ["a.c"], "flags": [], "libs": [], "levels": ["O0"], "toolchains": ["t"]}]]=])

# manifest(<name> <source object>) writes ${WORK}/<name>.json.
function(manifest name source)
  file(WRITE "${WORK}/${name}.json"
       "{\"schema\": 1, ${toolchains}, \"sources\": [${source}], ${build}}\n")
endfunction()

# A file:// URL: the path of an absolute POSIX directory already starts with "/"; a Windows path
# ("D:/...") needs one more, as in file:///D:/...
file(TO_CMAKE_PATH "${WORK}" work_path)
if(work_path MATCHES "^/")
  set(url_base "file://${work_path}")
else()
  set(url_base "file:///${work_path}")
endif()

function(source_of out archive sha)
  set(${out}
      "{\"name\": \"pkg\", \"version\": \"1\", \"licence\": \"MIT\", \"url\": \"${url_base}/${archive}\", \"sha256\": \"${sha}\", \"root\": \"pkg-1\"}"
      PARENT_SCOPE)
endfunction()

# expect_refused(<case> <manifest name> <regex>)
function(expect_refused label name expect)
  file(REMOVE_RECURSE "${WORK}/run-${name}")
  execute_process(COMMAND ${CMAKE_COMMAND} -DR1_WORK=${WORK}/run-${name}
                          -DR1_MANIFEST=${WORK}/${name}.json -DR1_STEP=fetch -P ${R1_SCRIPT}
                  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
  # CMake wraps long messages; compare with every run of white space made one space.
  string(REGEX REPLACE "[ \t\r\n]+" " " all "${output}${error}")
  if(result EQUAL 0)
    message(FATAL_ERROR "${label}: expected a refusal, the fetch succeeded:\n${all}")
  endif()
  if(NOT all MATCHES "${expect}")
    message(FATAL_ERROR "${label}: expected '${expect}', got (exit ${result}):\n${all}")
  endif()
  if(EXISTS "${WORK}/run-${name}/src/escape.txt" OR EXISTS "${WORK}/run-${name}/escape.txt")
    message(FATAL_ERROR "${label}: a member was written outside its directory")
  endif()
  message(STATUS "${label}: refused as expected")
endfunction()

# 1. An archive whose hash is not the pinned one is never unpacked.
string(REPLACE "a" "b" wrong_sha "${good_sha}")
if(wrong_sha STREQUAL good_sha)
  string(REPLACE "0" "1" wrong_sha "${good_sha}")
endif()
source_of(src good.tar ${wrong_sha})
manifest(hash "${src}")
expect_refused("hash mismatch" hash "the SHA-256 of .* is ${good_sha}, not the pinned ${wrong_sha}")
if(EXISTS "${WORK}/run-hash/downloads/good.tar" OR EXISTS "${WORK}/run-hash/downloads/good.tar.part")
  message(FATAL_ERROR "hash mismatch: the file that does not match was kept")
endif()

# 2. A member that climbs out with `..`.
source_of(src dotdot.tar ${dotdot_sha})
manifest(dotdot "${src}")
expect_refused("dot-dot member" dotdot "unsafe member 'pkg-1/\\.\\./escape\\.txt'")

# 3. A member outside the source's root directory.
source_of(src outside.tar ${outside_sha})
manifest(outside "${src}")
expect_refused("member outside the root" outside "member outside pkg-1/")

# 4. The schema: an unknown key, a missing key, a hash that is not 64 hex digits, an unsafe root.
source_of(src good.tar ${good_sha})
string(REPLACE "\"root\"" "\"extra\": 1, \"root\"" extra "${src}")
manifest(unknown "${extra}")
expect_refused("unknown key" unknown "unknown key 'extra' in source 0")
string(REPLACE ", \"sha256\": \"${good_sha}\"" "" missing "${src}")
manifest(missing "${missing}")
expect_refused("missing hash" missing "source 0 has no 'sha256'")
source_of(short good.tar "abc123")
manifest(short "${short}")
expect_refused("short hash" short "source pkg has no valid sha256")
string(REPLACE "\"root\": \"pkg-1\"" "\"root\": \"../up\"" up "${src}")
manifest(up "${up}")
expect_refused("unsafe root" up "unsafe root '\\.\\./up'")

# 5. The good archive is fetched, checked and unpacked.
manifest(good "${src}")
file(REMOVE_RECURSE "${WORK}/run-good")
execute_process(COMMAND ${CMAKE_COMMAND} -DR1_WORK=${WORK}/run-good -DR1_MANIFEST=${WORK}/good.json
                        -DR1_STEP=fetch -P ${R1_SCRIPT}
                RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0 OR NOT EXISTS "${WORK}/run-good/src/pkg/pkg-1/a.c")
  message(FATAL_ERROR "good archive: expected it unpacked (exit ${result}):\n${output}${error}")
endif()
message(STATUS "good archive: fetched and unpacked")
