# `donkey-cli project link` refuses a project it cannot link faithfully (G15-T2). Run as a script:
#   cmake -DDONKEY_CLI=<path> -DWORK_DIR=<dir> -DFIXTURE_DIR=<tests/fixtures/link> -P <this file>
# Each case fails the script with a message when the refusal is not what it should be.

if(NOT DEFINED DONKEY_CLI OR NOT DEFINED WORK_DIR OR NOT DEFINED FIXTURE_DIR)
  message(FATAL_ERROR "DONKEY_CLI, WORK_DIR and FIXTURE_DIR must be set")
endif()

set(DIR "${WORK_DIR}/project-link-refusals")
file(REMOVE_RECURSE "${DIR}")
file(MAKE_DIRECTORY "${DIR}")

# 1. A file that changed after it was saved is refused, and the refusal names the file.
set(DB "${DIR}/changed.db")
set(PROVIDER "${DIR}/libprovider.so.1")
configure_file("${FIXTURE_DIR}/libprovider.so.1" "${PROVIDER}" COPYONLY)
execute_process(COMMAND "${DONKEY_CLI}" project save "${DB}" "${FIXTURE_DIR}/libconsumer.so"
                RESULT_VARIABLE rc OUTPUT_QUIET ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "saving the consumer failed: ${err}")
endif()
execute_process(COMMAND "${DONKEY_CLI}" project save "${DB}" "${PROVIDER}"
                RESULT_VARIABLE rc OUTPUT_QUIET ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "saving the provider failed: ${err}")
endif()
file(APPEND "${PROVIDER}" "x")
execute_process(COMMAND "${DONKEY_CLI}" project link "${DB}"
                RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT rc EQUAL 1)
  message(FATAL_ERROR "a changed image must fail the link with exit 1, got ${rc}: ${out}${err}")
endif()
if(NOT err MATCHES "project.image_changed" OR NOT err MATCHES "libprovider.so.1")
  message(FATAL_ERROR "the refusal must name the changed image: ${err}")
endif()

# 2. A project with one image has nothing to link.
set(ONE "${DIR}/one.db")
execute_process(COMMAND "${DONKEY_CLI}" project save "${ONE}" "${FIXTURE_DIR}/libconsumer.so"
                RESULT_VARIABLE rc OUTPUT_QUIET ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "saving the single image failed: ${err}")
endif()
execute_process(COMMAND "${DONKEY_CLI}" project link "${ONE}"
                RESULT_VARIABLE rc OUTPUT_QUIET ERROR_VARIABLE err)
if(rc EQUAL 0)
  message(FATAL_ERROR "a project with one image must not link")
endif()
if(NOT err MATCHES "at least two images")
  message(FATAL_ERROR "the refusal must say why: ${err}")
endif()
message(STATUS "project link refusals: ok")
