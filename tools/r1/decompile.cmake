# R1 (G20-T2): decompile every binary that tools/r1/build.cmake built, one process per binary with a
# time limit, for `donkey-r1 measure` to count. Run in script mode:
#
#   cmake -DR1_WORK=<dir> -DDONKEY_CLI=<donkey-cli> -DOUT=<dir> [-DTIMEOUT=<seconds>] \
#         -P tools/r1/decompile.cmake
#
# Writes OUT/<binary>.json for each binary of R1_WORK/binaries.json. A run that fails or times out
# leaves no output file, which donkey-r1 then reports as that binary's error; this script itself
# fails only when it cannot run at all.

cmake_minimum_required(VERSION 3.25)

foreach(required R1_WORK DONKEY_CLI OUT)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "r1: ${required} is required")
  endif()
endforeach()
if(NOT DEFINED TIMEOUT)
  set(TIMEOUT 900)
endif()

file(READ "${R1_WORK}/binaries.json" binaries)
string(JSON count ERROR_VARIABLE error LENGTH "${binaries}" binaries)
if(error OR count EQUAL 0)
  message(FATAL_ERROR "r1: ${R1_WORK}/binaries.json lists no binaries")
endif()
# A toolchain whose programs run on another system's libraries names them as a sysroot in r1.json:
# the analysis binds the imports there (G24-T3), as that system's loader would.
file(READ "${CMAKE_CURRENT_LIST_DIR}/r1.json" manifest)
file(MAKE_DIRECTORY "${OUT}")
math(EXPR last "${count} - 1")
set(failed 0)
foreach(i RANGE ${last})
  string(JSON file GET "${binaries}" binaries ${i} file)
  if(file MATCHES "[/\\\\]" OR file STREQUAL "." OR file STREQUAL "..")
    message(FATAL_ERROR "r1: binaries.json names an unsafe file '${file}'")
  endif()
  string(JSON toolchain GET "${binaries}" binaries ${i} toolchain)
  string(JSON sysroot ERROR_VARIABLE no_sysroot GET "${manifest}" toolchains "${toolchain}" sysroot)
  set(scope)
  if(NOT no_sysroot)
    if(NOT IS_DIRECTORY "${sysroot}")
      message(FATAL_ERROR "r1: toolchain ${toolchain} needs its sysroot ${sysroot}")
    endif()
    set(scope --sysroot "${sysroot}")
  endif()
  set(output "${OUT}/${file}.json")
  file(REMOVE "${output}" "${output}.part")
  string(TIMESTAMP started "%s")
  execute_process(COMMAND "${DONKEY_CLI}" decompile "${R1_WORK}/out/${file}" --json
                          --no-pseudocode --max-functions 1000000 ${scope}
                  OUTPUT_FILE "${output}.part" ERROR_VARIABLE stderr_text
                  RESULT_VARIABLE result TIMEOUT ${TIMEOUT})
  string(TIMESTAMP finished "%s")
  math(EXPR seconds "${finished} - ${started}")
  if(result EQUAL 0)
    file(RENAME "${output}.part" "${output}")
    message(STATUS "r1: ${file}: ${seconds} s")
  else()
    file(REMOVE "${output}.part")
    math(EXPR failed "${failed} + 1")
    message(WARNING "r1: ${file}: decompile failed after ${seconds} s (${result}): ${stderr_text}")
  endif()
endforeach()
message(STATUS "r1: decompiled ${count} binaries, ${failed} failed")
