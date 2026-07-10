if(NOT DEFINED ORCHARDSEAL_BIN OR NOT EXISTS "${ORCHARDSEAL_BIN}")
    message(FATAL_ERROR "ORCHARDSEAL_BIN is missing: ${ORCHARDSEAL_BIN}")
endif()
if(NOT DEFINED MALICIOUS_ARCHIVE OR NOT EXISTS "${MALICIOUS_ARCHIVE}")
    message(FATAL_ERROR "MALICIOUS_ARCHIVE is missing: ${MALICIOUS_ARCHIVE}")
endif()
if(NOT DEFINED WORK_DIR)
    message(FATAL_ERROR "WORK_DIR is required")
endif()

file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${WORK_DIR}/temp")
set(marker "${WORK_DIR}/temp/orchardseal_escape_marker.txt")
file(REMOVE "${marker}")

execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" --audit --temp_folder "${WORK_DIR}/temp" "${MALICIOUS_ARCHIVE}"
    RESULT_VARIABLE audit_result
    OUTPUT_VARIABLE audit_output
    ERROR_VARIABLE audit_error
)
if(audit_result EQUAL 0)
    message(FATAL_ERROR "Unsafe archive unexpectedly passed audit.\n${audit_error}\n${audit_output}")
endif()
if(EXISTS "${marker}")
    message(FATAL_ERROR "Archive traversal created a file outside the extraction root: ${marker}")
endif()
file(GLOB extraction_leftovers "${WORK_DIR}/temp/orchardseal_audit_*")
if(extraction_leftovers)
    message(FATAL_ERROR "Failed extraction left temporary content behind: ${extraction_leftovers}")
endif()
