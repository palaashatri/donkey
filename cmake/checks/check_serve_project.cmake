# Checks `donkey-cli serve --project` end to end (G11-T1, G11-T2): decompile and annotations.list
# with a project, the write methods only with --allow-write, writes that persist to the database
# (read back with `donkey-cli project annotations`), and the refusals without a project.
# Inputs: DONKEY_CLI (the binary), FIXTURE (tiny-elf-x86_64), WORK_DIR.

if(NOT DONKEY_CLI OR NOT FIXTURE OR NOT WORK_DIR)
  message(FATAL_ERROR "check_serve_project: DONKEY_CLI, FIXTURE and WORK_DIR are required")
endif()

# Passes when one response line contains every fragment (literal text, not a pattern).
function(expect_response output)
  string(REPLACE ";" " " cleaned "${output}")
  string(REPLACE "\n" ";" response_lines "${cleaned}")
  foreach(response IN LISTS response_lines)
    set(every TRUE)
    foreach(fragment IN LISTS ARGN)
      string(FIND "${response}" "${fragment}" position)
      if(position EQUAL -1)
        set(every FALSE)
      endif()
    endforeach()
    if(every)
      return()
    endif()
  endforeach()
  message(FATAL_ERROR "no response line contains all of: ${ARGN}\n${output}")
endfunction()

string(REPLACE "\\" "/" fixture_path "${FIXTURE}")
set(database "${WORK_DIR}/serve-project.db")
file(REMOVE "${database}" "${database}-wal" "${database}-shm")

execute_process(COMMAND "${DONKEY_CLI}" project save "${database}" "${fixture_path}" --json
                OUTPUT_QUIET RESULT_VARIABLE save_status)
if(NOT save_status EQUAL 0)
  message(FATAL_ERROR "project save exited with ${save_status}")
endif()

# With a project and --allow-write: decompile, list, write, list again, and a refused type.
set(requests_file "${WORK_DIR}/serve-project-writes.jsonl")
file(WRITE "${requests_file}"
"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"open\",\"params\":{\"path\":\"${fixture_path}\"}}
{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"decompile\",\"params\":{\"address\":\"0x400100\"}}
{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"decompile\",\"params\":{\"address\":\"0x400101\"}}
{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"annotations.list\"}
{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"rename\",\"params\":{\"address\":\"0x400109\",\"text\":\"helper\"}}
{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"comment\",\"params\":{\"address\":\"0x400109\",\"text\":\"a note\"}}
{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"annotations.list\"}
{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"type.apply\",\"params\":{\"address\":\"0x400100\",\"type_id\":999}}
")
execute_process(COMMAND "${DONKEY_CLI}" serve --project "${database}" --allow-write
                INPUT_FILE "${requests_file}"
                OUTPUT_VARIABLE output
                ERROR_VARIABLE error
                RESULT_VARIABLE status)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "serve --project exited with ${status}: ${error}")
endif()
expect_response("${output}" "\"id\": 2" "\"name\": \"_start\"" "\"pseudocode\"")
expect_response("${output}" "\"id\": 3" "\"error\"" "rpc.unknown_function")
expect_response("${output}" "\"id\": 4" "\"count\": 0")
expect_response("${output}" "\"id\": 5" "\"method\": \"rename\"" "\"text\": \"helper\"")
expect_response("${output}" "\"id\": 6" "\"method\": \"comment\"" "\"text\": \"a note\"")
expect_response("${output}" "\"id\": 7" "\"kind\": \"rename\"" "\"text\": \"helper\"" "\"kind\": \"comment\"" "\"text\": \"a note\"")
expect_response("${output}" "\"id\": 8" "\"error\"" "project.type_not_found")

# The writes are in the database, not only in the server's memory.
execute_process(COMMAND "${DONKEY_CLI}" project annotations "${database}" 1 --json
                OUTPUT_VARIABLE stored RESULT_VARIABLE stored_status)
if(NOT stored_status EQUAL 0)
  message(FATAL_ERROR "project annotations exited with ${stored_status}")
endif()
string(FIND "${stored}" "helper" stored_rename)
string(FIND "${stored}" "a note" stored_comment)
if(stored_rename EQUAL -1 OR stored_comment EQUAL -1)
  message(FATAL_ERROR "the writes did not persist:\n${stored}")
endif()

# With a project but without --allow-write: reads work, writes are refused.
set(read_only "${WORK_DIR}/serve-project-readonly.jsonl")
file(WRITE "${read_only}"
"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"open\",\"params\":{\"path\":\"${fixture_path}\"}}
{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"annotations.list\"}
{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"rename\",\"params\":{\"address\":\"0x400109\",\"text\":\"other\"}}
")
execute_process(COMMAND "${DONKEY_CLI}" serve --project "${database}"
                INPUT_FILE "${read_only}"
                OUTPUT_VARIABLE output RESULT_VARIABLE status)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "read-only serve exited with ${status}")
endif()
expect_response("${output}" "\"id\": 2" "\"text\": \"helper\"")
expect_response("${output}" "\"id\": 3" "rpc.write_disabled" "--allow-write was not given")

# Without a project: annotations.list says it needs one, and --allow-write without --project is a
# usage error.
set(no_project "${WORK_DIR}/serve-no-project.jsonl")
file(WRITE "${no_project}"
"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"open\",\"params\":{\"path\":\"${fixture_path}\"}}
{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"annotations.list\"}
")
execute_process(COMMAND "${DONKEY_CLI}" serve
                INPUT_FILE "${no_project}"
                OUTPUT_VARIABLE output RESULT_VARIABLE status)
expect_response("${output}" "\"id\": 2" "rpc.no_project")
execute_process(COMMAND "${DONKEY_CLI}" serve --allow-write
                OUTPUT_QUIET ERROR_QUIET RESULT_VARIABLE usage_status)
if(NOT usage_status EQUAL 2)
  message(FATAL_ERROR "--allow-write without --project should exit 2, got ${usage_status}")
endif()

message(STATUS "serve --project: decompile, annotations, writes persisted, refusals hold")
