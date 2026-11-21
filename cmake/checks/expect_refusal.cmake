# Runs a command that must be refused: it has to exit with a nonzero status AND print the expected
# diagnostic. CTest's PASS_REGULAR_EXPRESSION alone ignores the exit status, so a command that
# printed the message and exited 0 would pass.
# Inputs: REFUSED_COMMAND (a ;-separated list: the program and its arguments), EXPECT (a regular expression
# the output, stdout and stderr together, must match).

if(NOT DEFINED REFUSED_COMMAND OR NOT DEFINED EXPECT)
  message(FATAL_ERROR "expect_refusal: REFUSED_COMMAND and EXPECT are required")
endif()

execute_process(COMMAND ${REFUSED_COMMAND}
                RESULT_VARIABLE result
                OUTPUT_VARIABLE output
                ERROR_VARIABLE error
                TIMEOUT 300)
set(all "${output}${error}")
# A crash or a timeout gives a message ("Segmentation fault", "Process terminated due to timeout"),
# not a number: that is not a refusal either.
if(NOT result MATCHES "^[0-9]+$")
  message(FATAL_ERROR "expected a refusal, but the command did not exit normally (${result}):\n${all}")
endif()
if(result EQUAL 0)
  message(FATAL_ERROR "expected a refusal (a nonzero exit status), got 0:\n${all}")
endif()
if(NOT all MATCHES "${EXPECT}")
  message(FATAL_ERROR "expected output matching '${EXPECT}' (exit ${result}):\n${all}")
endif()
