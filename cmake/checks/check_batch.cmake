# Checks `donkey-cli batch` (G11-T3): a JSON array of requests runs in order in one session and
# prints one JSON array of responses. Notifications have no response; a malformed element gets its
# own error in place. A file that is not an array, or does not exist, fails with exit 1.
# Inputs: DONKEY_CLI (the binary), FIXTURE (tiny-elf-x86_64), WORK_DIR.

if(NOT DONKEY_CLI OR NOT FIXTURE OR NOT WORK_DIR)
  message(FATAL_ERROR "check_batch: DONKEY_CLI, FIXTURE and WORK_DIR are required")
endif()

string(REPLACE "\\" "/" fixture_path "${FIXTURE}")
set(script "${WORK_DIR}/batch-script.json")
file(WRITE "${script}"
"[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"open\",\"params\":{\"path\":\"${fixture_path}\"}},
{\"jsonrpc\":\"2.0\",\"method\":\"hello\"},
{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"callgraph\"},
\"not a request\",
{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"xrefs\",\"params\":{\"address\":\"0x400109\"}}]
")

execute_process(COMMAND "${DONKEY_CLI}" batch "${script}"
                OUTPUT_VARIABLE output
                ERROR_VARIABLE error
                RESULT_VARIABLE status)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "batch exited with ${status}: ${error}")
endif()

# string(JSON) fails the script when the output is not valid JSON.
string(JSON response_count LENGTH "${output}")
if(NOT response_count EQUAL 4)
  message(FATAL_ERROR "expected 4 responses (the notification has none), got ${response_count}:\n${output}")
endif()
string(JSON first_id GET "${output}" 0 "id")
string(JSON second_id GET "${output}" 1 "id")
string(JSON third_id_type TYPE "${output}" 2 "id")
string(JSON fourth_id GET "${output}" 3 "id")
if(NOT first_id EQUAL 1 OR NOT second_id EQUAL 2 OR NOT fourth_id EQUAL 3)
  message(FATAL_ERROR "responses are out of order: ${first_id}, ${second_id}, ${fourth_id}")
endif()
if(NOT third_id_type STREQUAL "NULL")
  message(FATAL_ERROR "the malformed element should answer with id null, got ${third_id_type}")
endif()
string(JSON bad_code GET "${output}" 2 "error" "code")
if(NOT bad_code EQUAL -32600)
  message(FATAL_ERROR "the malformed element should be invalid_request (-32600), got ${bad_code}")
endif()
string(JSON edge_count GET "${output}" 1 "result" "edge_count")
if(NOT edge_count EQUAL 1)
  message(FATAL_ERROR "callgraph after open found ${edge_count} edges, expected 1")
endif()

# A file that is not an array, and a file that does not exist, both fail with exit 1.
set(object_script "${WORK_DIR}/batch-object.json")
file(WRITE "${object_script}" "{}")
execute_process(COMMAND "${DONKEY_CLI}" batch "${object_script}"
                OUTPUT_QUIET ERROR_QUIET RESULT_VARIABLE object_status)
if(NOT object_status EQUAL 1)
  message(FATAL_ERROR "a script that is not an array should exit 1, got ${object_status}")
endif()
execute_process(COMMAND "${DONKEY_CLI}" batch "${WORK_DIR}/does-not-exist.json"
                OUTPUT_QUIET ERROR_QUIET RESULT_VARIABLE missing_status)
if(NOT missing_status EQUAL 1)
  message(FATAL_ERROR "a missing script should exit 1, got ${missing_status}")
endif()

message(STATUS "batch: 4 ordered responses, notification silent, bad inputs exit 1")
