function(orchardseal_apply_default_options target_name)
    target_compile_features(${target_name} PRIVATE cxx_std_17)
    set_target_properties(${target_name} PROPERTIES CXX_EXTENSIONS OFF)

    if(MSVC)
        target_compile_options(${target_name} PRIVATE /permissive- /utf-8 /W4)
        target_compile_definitions(${target_name} PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
        if(ORCHARDSEAL_WARNINGS_AS_ERRORS)
            target_compile_options(${target_name} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target_name} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wno-unused-parameter
            -Wno-missing-field-initializers
            -Wno-deprecated-declarations
        )
        if(ORCHARDSEAL_WARNINGS_AS_ERRORS)
            target_compile_options(${target_name} PRIVATE -Werror)
        endif()
    endif()
endfunction()
