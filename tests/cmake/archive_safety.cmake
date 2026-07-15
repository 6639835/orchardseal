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

# A small archive with an extreme expansion ratio must be rejected before any
# payload is written. Generate it at test time so the repository does not carry
# a decompression-bomb fixture.
set(ratio_source "${WORK_DIR}/ratio-source")
set(ratio_archive "${WORK_DIR}/high-ratio.zip")
file(MAKE_DIRECTORY "${ratio_source}/Payload/Bomb.app")
string(REPEAT "0" 2097152 compressible_data)
file(WRITE "${ratio_source}/Payload/Bomb.app/padding" "${compressible_data}")
unset(compressible_data)
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E tar cf "${ratio_archive}" --format=zip Payload
    WORKING_DIRECTORY "${ratio_source}"
    RESULT_VARIABLE archive_result
    ERROR_VARIABLE archive_error
)
if(NOT archive_result EQUAL 0)
    message(FATAL_ERROR "Could not create high-ratio test archive: ${archive_error}")
endif()

execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" --audit --temp_folder "${WORK_DIR}/temp" "${ratio_archive}"
    RESULT_VARIABLE ratio_result
    OUTPUT_VARIABLE ratio_output
    ERROR_VARIABLE ratio_error
)
if(ratio_result EQUAL 0 OR NOT ratio_error MATCHES "Suspicious compression ratio")
    message(FATAL_ERROR "High-ratio archive did not fail at the extraction limit.\n${ratio_error}\n${ratio_output}")
endif()
file(GLOB ratio_leftovers "${WORK_DIR}/temp/orchardseal_audit_*")
if(ratio_leftovers)
    message(FATAL_ERROR "High-ratio extraction left temporary content behind: ${ratio_leftovers}")
endif()
