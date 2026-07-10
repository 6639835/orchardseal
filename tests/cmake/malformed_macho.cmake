if(NOT DEFINED ORCHARDSEAL_BIN OR NOT EXISTS "${ORCHARDSEAL_BIN}")
    message(FATAL_ERROR "ORCHARDSEAL_BIN is missing: ${ORCHARDSEAL_BIN}")
endif()
if(NOT DEFINED MALFORMED_MACHO OR NOT EXISTS "${MALFORMED_MACHO}")
    message(FATAL_ERROR "MALFORMED_MACHO is missing: ${MALFORMED_MACHO}")
endif()

execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" --audit --audit-format json "${MALFORMED_MACHO}"
    RESULT_VARIABLE audit_result
    OUTPUT_VARIABLE audit_output
    ERROR_VARIABLE audit_error
)
if(NOT audit_result EQUAL 3)
    message(FATAL_ERROR
        "Malformed Mach-O should produce audit exit code 3; got ${audit_result}.\n"
        "stderr:\n${audit_error}\nstdout:\n${audit_output}")
endif()

string(FIND "${audit_output}" "\"code\": \"MACHO_INVALID\"" issue_position)
if(issue_position EQUAL -1)
    message(FATAL_ERROR "Malformed Mach-O report did not contain MACHO_INVALID.\n${audit_output}")
endif()
string(FIND "${audit_output}" "\"ready_for_signing\": false" readiness_position)
if(readiness_position EQUAL -1)
    message(FATAL_ERROR "Malformed Mach-O report did not block signing.\n${audit_output}")
endif()
