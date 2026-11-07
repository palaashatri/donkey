# Checks `donkey-cli serve` end to end (G11-T1): a scripted session over stdin, the framing and
# error codes, notifications (no response), and the 16 MiB request limit, after which the next
# request is still answered. Inputs: DONKEY_CLI (the binary), FIXTURE (tiny-elf-x86_64), WORK_DIR.

if(NOT DONKEY_CLI OR NOT FIXTURE OR NOT WORK_DIR)
  message(FATAL_ERROR "check_serve: DONKEY_CLI, FIXTURE and WORK_DIR are required")
endif()

# Passes when one response line contains every fragment (literal text, not a pattern).
function(expect_response output)
  # CMake lists split on semicolons, which responses may contain; the fragments never do.
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
set(requests_file "${WORK_DIR}/serve-session.jsonl")
file(WRITE "${requests_file}"
"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"hello\"}
{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"open\",\"params\":{\"path\":\"${fixture_path}\"}}
{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"functions\",\"params\":{\"limit\":5}}
{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"disasm\",\"params\":{\"address\":\"0x400100\",\"count\":2}}
{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"xrefs\",\"params\":{\"address\":\"0x400109\"}}
{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"callgraph\"}
{\"jsonrpc\":\"2.0\",\"method\":\"hello\"}
not json
{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"decompile\"}
{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"rename\"}
{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"open\",\"params\":{\"path\":\"/does/not/exist\"}}
{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"info\",\"params\":{\"limit\":0}}
")

execute_process(COMMAND "${DONKEY_CLI}" serve
                INPUT_FILE "${requests_file}"
                OUTPUT_VARIABLE output
                ERROR_VARIABLE error
                RESULT_VARIABLE status)
if(NOT status EQUAL 0)
  message(FATAL_ERROR "serve exited with ${status}: ${error}")
endif()

# Eleven requests get a response: six results, the parse error, and four errors. The
# notification (no id) gets none.
string(REGEX MATCHALL "\n" newlines "${output}")
list(LENGTH newlines response_count)
if(NOT response_count EQUAL 11)
  message(FATAL_ERROR "expected 11 response lines, got ${response_count}:\n${output}")
endif()

expect_response("${output}"
  "\"id\": 1, \"result\": {\"protocol\": \"donkey.rpc.v1\"")
expect_response("${output}"
  "\"id\": 2, \"result\": {\"path\": " "\"format\": \"ELF\"" "\"architecture\": \"x86_64\"")
expect_response("${output}"
  "\"id\": 3, \"result\": {\"status\": \"Complete\"")
expect_response("${output}"
  "\"id\": 4, \"result\": {\"address\": \"0x400100\", \"instructions\": [{\"address\": \"0x400100\"")
expect_response("${output}"
  "\"from\": \"0x400104\", \"to\": \"0x400109\", \"kind\": \"call\"")
expect_response("${output}"
  "\"caller\": \"0x400100\", \"callee\": \"0x400109\"")
expect_response("${output}"
  "\"id\": null, \"error\": {\"code\": -32700" "\"donkey_code\": \"rpc.parse\"")
expect_response("${output}"
  "\"id\": 7, \"error\": {\"code\": -32602" "\"donkey_code\": \"rpc.invalid_params\"")
expect_response("${output}"
  "\"id\": 8, \"error\": {\"code\": -32003" "\"donkey_code\": \"rpc.write_disabled\"")
expect_response("${output}"
  "\"id\": 9, \"error\": {\"code\": -32000" "\"donkey_code\": \"rpc.open_failed\"")
expect_response("${output}"
  "\"id\": 10, \"error\": {\"code\": -32602" "\"donkey_code\": \"rpc.invalid_params\"")

# A request over the limit is refused with its own code, and the request after it still runs.
string(REPEAT "x" 16777217 oversized)
set(large_file "${WORK_DIR}/serve-oversized.jsonl")
file(WRITE "${large_file}" "${oversized}\n{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"hello\"}\n")
execute_process(COMMAND "${DONKEY_CLI}" serve
                INPUT_FILE "${large_file}"
                OUTPUT_VARIABLE large_output
                ERROR_VARIABLE large_error
                RESULT_VARIABLE large_status)
if(NOT large_status EQUAL 0)
  message(FATAL_ERROR "serve exited with ${large_status} on the oversized request: ${large_error}")
endif()
expect_response("${large_output}" "\"donkey_code\": \"rpc.too_large\"")
expect_response("${large_output}" "\"id\": 11, \"result\": {\"protocol\": \"donkey.rpc.v1\"")

message(STATUS "serve: 11 responses, notifications silent, oversized request refused")
