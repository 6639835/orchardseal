if(NOT DEFINED ORCHARDSEAL_BIN OR NOT EXISTS "${ORCHARDSEAL_BIN}")
    message(FATAL_ERROR "ORCHARDSEAL_BIN is missing: ${ORCHARDSEAL_BIN}")
endif()
if(NOT DEFINED FIXTURE_BINARY OR NOT EXISTS "${FIXTURE_BINARY}")
    message(FATAL_ERROR "FIXTURE_BINARY is missing: ${FIXTURE_BINARY}")
endif()
if(NOT DEFINED WORK_DIR)
    message(FATAL_ERROR "WORK_DIR is required")
endif()

function(assert_contains value expected context)
    string(FIND "${value}" "${expected}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "${context}: expected output to contain '${expected}'.\nOutput:\n${value}")
    endif()
endfunction()

file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${WORK_DIR}")

execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" --audit --audit-format json "${FIXTURE_BINARY}"
    RESULT_VARIABLE macho_result
    OUTPUT_VARIABLE macho_output
    ERROR_VARIABLE macho_error
)
if(NOT macho_result EQUAL 0)
    message(FATAL_ERROR "Mach-O audit failed with ${macho_result}: ${macho_error}\n${macho_output}")
endif()
assert_contains("${macho_output}" "\"product\": \"OrchardSeal\"" "Mach-O audit")
assert_contains("${macho_output}" "\"engine\": \"SealCheck\"" "Mach-O audit")
assert_contains("${macho_output}" "\"input_type\": \"mach-o\"" "Mach-O audit")
assert_contains("${macho_output}" "\"architecture\": \"arm64\"" "Mach-O audit")

set(app_dir "${WORK_DIR}/Payload/AuditFixture.app")
file(MAKE_DIRECTORY "${app_dir}")
configure_file("${FIXTURE_BINARY}" "${app_dir}/AuditFixture" COPYONLY)
file(WRITE "${app_dir}/Info.plist" [=[<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.orchardseal.audit-fixture</string>
    <key>CFBundleExecutable</key><string>AuditFixture</string>
    <key>CFBundleName</key><string>Audit Fixture</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>MinimumOSVersion</key><string>12.0</string>
</dict>
</plist>
]=])

set(report_file "${WORK_DIR}/reports/audit.json")
execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" --audit --audit-format json --audit-report "${report_file}" "${app_dir}"
    RESULT_VARIABLE bundle_result
    OUTPUT_VARIABLE bundle_output
    ERROR_VARIABLE bundle_error
)
if(NOT bundle_result EQUAL 0)
    message(FATAL_ERROR "Bundle audit failed with ${bundle_result}: ${bundle_error}\n${bundle_output}")
endif()
assert_contains("${bundle_output}" "com.orchardseal.audit-fixture" "Bundle audit")
assert_contains("${bundle_output}" "\"main_bundle\": true" "Bundle audit")
if(NOT EXISTS "${report_file}")
    message(FATAL_ERROR "Audit report file was not created")
endif()
file(READ "${report_file}" saved_report)
assert_contains("${saved_report}" "\"schema_version\": \"1.0\"" "Saved audit report")

execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" --audit --strict-audit "${app_dir}"
    RESULT_VARIABLE strict_result
    OUTPUT_VARIABLE strict_output
    ERROR_VARIABLE strict_error
)
if(NOT strict_result EQUAL 3)
    message(FATAL_ERROR "Strict audit should return 3 for warnings; got ${strict_result}: ${strict_error}\n${strict_output}")
endif()

set(ipa_file "${WORK_DIR}/AuditFixture.ipa")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E tar cf "${ipa_file}" --format=zip Payload
    WORKING_DIRECTORY "${WORK_DIR}"
    RESULT_VARIABLE archive_result
    ERROR_VARIABLE archive_error
)
if(NOT archive_result EQUAL 0)
    message(FATAL_ERROR "Could not create IPA fixture: ${archive_error}")
endif()
execute_process(
    COMMAND "${ORCHARDSEAL_BIN}" --audit --audit-format json --temp_folder "${WORK_DIR}" "${ipa_file}"
    RESULT_VARIABLE ipa_result
    OUTPUT_VARIABLE ipa_output
    ERROR_VARIABLE ipa_error
)
if(NOT ipa_result EQUAL 0)
    message(FATAL_ERROR "IPA audit failed with ${ipa_result}: ${ipa_error}\n${ipa_output}")
endif()
assert_contains("${ipa_output}" "\"input_type\": \"ipa-archive\"" "IPA audit")
assert_contains("${ipa_output}" "com.orchardseal.audit-fixture" "IPA audit")
