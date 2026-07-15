if(NOT DEFINED ORCHARDSEAL_BIN OR NOT EXISTS "${ORCHARDSEAL_BIN}")
    message(FATAL_ERROR "ORCHARDSEAL_BIN is missing: ${ORCHARDSEAL_BIN}")
endif()
if(NOT DEFINED FIXTURE_BINARY OR NOT EXISTS "${FIXTURE_BINARY}")
    message(FATAL_ERROR "FIXTURE_BINARY is missing: ${FIXTURE_BINARY}")
endif()

execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" --audit --audit-format json "${FIXTURE_BINARY}" extra-input
    RESULT_VARIABLE extra_result
    OUTPUT_VARIABLE extra_output
    ERROR_VARIABLE extra_error
)
if(NOT extra_result EQUAL 2 OR NOT extra_output STREQUAL "")
    message(FATAL_ERROR "Extra operands must fail with exit 2 and empty stdout.\n${extra_error}\n${extra_output}")
endif()

execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" "${FIXTURE_BINARY}" --audit --audit-format json
    RESULT_VARIABLE reordered_result
    OUTPUT_VARIABLE reordered_output
    ERROR_VARIABLE reordered_error
)
if(NOT reordered_result EQUAL 0 OR NOT reordered_output MATCHES "\"schema_version\"")
    message(FATAL_ERROR "Options after the input operand must be accepted.\n${reordered_error}\n${reordered_output}")
endif()

set(unicode_directory "${CMAKE_CURRENT_BINARY_DIR}/orchardseal-应用-😀")
file(REMOVE_RECURSE "${unicode_directory}")
file(MAKE_DIRECTORY "${unicode_directory}")
get_filename_component(fixture_name "${FIXTURE_BINARY}" NAME)
file(COPY "${FIXTURE_BINARY}" DESTINATION "${unicode_directory}")
execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" --audit --audit-format json "${unicode_directory}/${fixture_name}"
    RESULT_VARIABLE unicode_result
    OUTPUT_VARIABLE unicode_output
    ERROR_VARIABLE unicode_error
)
file(REMOVE_RECURSE "${unicode_directory}")
if(NOT unicode_result EQUAL 0 OR NOT unicode_output MATCHES "\"schema_version\"")
    message(FATAL_ERROR "UTF-8 input paths must work end-to-end.\n${unicode_error}\n${unicode_output}")
endif()

set(secret "orchardseal-cli-secret-sentinel")
execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" -d -p "${secret}" --audit --audit-format json "${FIXTURE_BINARY}"
    RESULT_VARIABLE debug_result
    OUTPUT_VARIABLE debug_output
    ERROR_VARIABLE debug_error
)
if(NOT debug_result EQUAL 0)
    message(FATAL_ERROR "Debug audit failed.\n${debug_error}\n${debug_output}")
endif()
string(FIND "${debug_output}${debug_error}" "${secret}" secret_position)
if(NOT secret_position EQUAL -1)
    message(FATAL_ERROR "Debug logging exposed a password sentinel.")
endif()
string(ASCII 27 escape_character)
string(FIND "${debug_output}${debug_error}" "${escape_character}" escape_position)
if(NOT escape_position EQUAL -1)
    message(FATAL_ERROR "Non-interactive CLI output contained ANSI color escapes.")
endif()
if(NOT debug_output MATCHES "\"schema_version\"")
    message(FATAL_ERROR "JSON report was not written to stdout.\n${debug_output}")
endif()

execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" --audit --audit-format json "${FIXTURE_BINARY}.missing"
    RESULT_VARIABLE missing_result
    OUTPUT_VARIABLE missing_output
    ERROR_VARIABLE missing_error
)
if(NOT missing_result EQUAL 1 OR NOT missing_output STREQUAL "" OR missing_error STREQUAL "")
    message(FATAL_ERROR "Operational errors must use stderr and leave stdout empty.\n${missing_error}\n${missing_output}")
endif()

foreach(flag IN ITEMS --help --version)
    execute_process(
        COMMAND "${ORCHARDSEAL_BIN}" "${flag}"
        RESULT_VARIABLE info_result
        OUTPUT_VARIABLE info_output
        ERROR_VARIABLE info_error
    )
    if(NOT info_result EQUAL 0 OR info_output STREQUAL "" OR NOT info_error STREQUAL "")
        message(FATAL_ERROR "${flag} must succeed on stdout without diagnostics.\n${info_error}\n${info_output}")
    endif()
    if(flag STREQUAL "--help")
        string(FIND "${info_output}" "—" unicode_heading_position)
        string(ASCII 13 carriage_return)
        string(FIND "${info_output}" "${carriage_return}" carriage_return_position)
        if(unicode_heading_position EQUAL -1 OR NOT carriage_return_position EQUAL -1)
            message(FATAL_ERROR "Help output must preserve UTF-8 and raw LF bytes.\n${info_output}")
        endif()
    endif()

    execute_process(
        COMMAND "${ORCHARDSEAL_BIN}" "${flag}" unexpected-input
        RESULT_VARIABLE invalid_info_result
        OUTPUT_VARIABLE invalid_info_output
        ERROR_VARIABLE invalid_info_error
    )
    if(NOT invalid_info_result EQUAL 2 OR NOT invalid_info_output STREQUAL "" OR invalid_info_error STREQUAL "")
        message(FATAL_ERROR "${flag} with an operand must fail with exit 2 and diagnostics only on stderr.\n${invalid_info_error}\n${invalid_info_output}")
    endif()
endforeach()
