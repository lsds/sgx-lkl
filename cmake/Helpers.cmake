include_guard(GLOBAL)

function(mkdir DIRECTORY)
	execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory "${DIRECTORY}")
endfunction()

function(touch FILE_NAME)
	execute_process(COMMAND ${CMAKE_COMMAND} -E touch "${FILE_NAME}")
endfunction()

function(create_empty FILE_NAME)
    if (NOT EXISTS "${FILENAME}")
        touch("${FILE_NAME}")
    endif()
endfunction()

function(get_external_project_property EP_NAME PROP_NAME VAR_NAME)
    ExternalProject_Get_property(${EP_NAME} ${PROP_NAME})
    set(${VAR_NAME} "${${PROP_NAME}}" PARENT_SCOPE)
endfunction()

function(get_c_compiler_include_dir VAR_NAME)
    execute_process(
        COMMAND "${PROJECT_SOURCE_DIR}/cmake/get_c_compiler_inc_dir.sh" "${CMAKE_C_COMPILER}"
        OUTPUT_VARIABLE stdout
        ERROR_VARIABLE stdout
        RESULT_VARIABLE exit_code
    )
    if (NOT exit_code EQUAL 0)
        message(FATAL_ERROR "Could not determine the C compiler include dir: ${stdout}")
    endif()
    set(${VAR_NAME} "${stdout}" PARENT_SCOPE)
endfunction()

function(get_c_compiler_rt_library VAR_NAME)
    get_c_compiler_include_dir(cc_inc_dir)
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
        find_library(rt_library
            NAMES libgcc.a
            PATHS "${cc_inc_dir}/.."
            NO_DEFAULT_PATH
        )
    elseif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
        find_library(rt_library
            NAMES libclang_rt.builtins-x86_64.a
            PATHS "${cc_inc_dir}/../lib/linux"
            NO_DEFAULT_PATH
        )
    else()
        message(FATAL_ERROR "Unsupported compiler: ${CMAKE_C_COMPILER_ID}")
    endif()
    if (NOT rt_library)
        message(FATAL_ERROR "Could not find the C compiler runtime library")
    endif()
    set(${VAR_NAME} "${rt_library}" PARENT_SCOPE)
endfunction()