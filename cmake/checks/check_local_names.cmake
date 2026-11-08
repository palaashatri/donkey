# Checks the local names of a project end to end (G12-T3): a parameter and a frame slot are saved
# with `donkey-cli project local-name`, `decompile --project` shows them, a name the decompiler
# refuses fails the command, a key that names nothing leaves a note, and a cleared name goes away.
# Inputs: DONKEY_CLI (the binary), FIXTURE (tests/fixtures/names/add_three), WORK_DIR.

if(NOT DONKEY_CLI OR NOT FIXTURE OR NOT WORK_DIR)
  message(FATAL_ERROR "check_local_names: DONKEY_CLI, FIXTURE and WORK_DIR are required")
endif()

set(DATABASE "${WORK_DIR}/local_names_check.db")
file(REMOVE "${DATABASE}")
# The address of add_three in the fixture (tests/fixtures/names/PROVENANCE.md).
set(ADDRESS "0x401120")

# Runs donkey-cli. Sets last_result and last_output for the caller.
function(run_cli)
  execute_process(COMMAND "${DONKEY_CLI}" ${ARGN}
                  RESULT_VARIABLE result
                  OUTPUT_VARIABLE output
                  ERROR_VARIABLE error
                  TIMEOUT 120)
  set(last_result "${result}" PARENT_SCOPE)
  set(last_output "${output}${error}" PARENT_SCOPE)
endfunction()

function(require_success what)
  if(NOT last_result EQUAL 0)
    message(FATAL_ERROR "${what} failed (exit ${last_result}):\n${last_output}")
  endif()
endfunction()

function(require_output text)
  string(FIND "${last_output}" "${text}" position)
  if(position EQUAL -1)
    message(FATAL_ERROR "expected '${text}' in the output:\n${last_output}")
  endif()
endfunction()

function(require_no_output text)
  string(FIND "${last_output}" "${text}" position)
  if(NOT position EQUAL -1)
    message(FATAL_ERROR "'${text}' must not appear in the output:\n${last_output}")
  endif()
endfunction()

run_cli(project save "${DATABASE}" "${FIXTURE}")
require_success("project save")

# The parameter and the frame slot at rbp-8 take the names.
run_cli(project local-name "${DATABASE}" 1 ${ADDRESS} arg:0 value)
require_success("project local-name arg:0")
run_cli(project local-name "${DATABASE}" 1 ${ADDRESS} frame:rbp:-8 scratch)
require_success("project local-name frame:rbp:-8")

run_cli(project local-names "${DATABASE}" 1)
require_success("project local-names")
require_output("arg:0")
require_output("frame:rbp:-8")

run_cli(decompile "${FIXTURE}" --function ${ADDRESS} --project "${DATABASE}")
require_success("decompile with names")
require_output("u32 add_three(u32 value)")
require_output("u32 scratch;")
require_output("scratch = (u32)rax;")

# A name the project accepts but the decompiler refuses (a C keyword) fails the command.
run_cli(project local-name "${DATABASE}" 1 ${ADDRESS} arg:0 int)
require_success("project local-name with a keyword")
run_cli(decompile "${FIXTURE}" --function ${ADDRESS} --project "${DATABASE}")
if(last_result EQUAL 0)
  message(FATAL_ERROR "a keyword name must fail decompile:\n${last_output}")
endif()
require_output("ir.local_name_invalid")

# A key that names nothing is kept, and the decompiler says so in a note.
run_cli(project local-name "${DATABASE}" 1 ${ADDRESS} arg:0 value)
require_success("project local-name arg:0 again")
run_cli(project local-name "${DATABASE}" 1 ${ADDRESS} frame:rsp:16 gone)
require_success("project local-name frame:rsp:16")
run_cli(decompile "${FIXTURE}" --function ${ADDRESS} --project "${DATABASE}")
require_success("decompile with a stale key")
require_output("local key 'frame:rsp:16' names no local of this function")

# Clearing the slot's name leaves its access in the address form.
run_cli(project local-name "${DATABASE}" 1 ${ADDRESS} frame:rbp:-8 --clear)
require_success("project local-name --clear")
run_cli(project local-names "${DATABASE}" 1 --json)
require_success("project local-names --json")
require_no_output("frame:rbp:-8")
run_cli(decompile "${FIXTURE}" --function ${ADDRESS} --project "${DATABASE}")
require_success("decompile after clear")
require_output("u32 add_three(u32 value)")
require_no_output("u32 scratch;")
