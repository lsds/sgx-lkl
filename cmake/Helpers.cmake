function(mkdir DIRECTORY)
	execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory "${DIRECTORY}")
endfunction()

function(touch FILE_NAME)
	execute_process(COMMAND ${CMAKE_COMMAND} -E touch "${FILE_NAME}")
endfunction()

function(get_external_project_property EP_NAME PROP_NAME VAR_NAME)
    ExternalProject_Get_property(${EP_NAME} ${PROP_NAME})
    set(${VAR_NAME} "${${PROP_NAME}}" PARENT_SCOPE)
endfunction()
