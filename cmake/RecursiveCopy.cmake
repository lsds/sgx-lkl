include_guard(GLOBAL)

function(copy_source_directory_to_output DIR EXCLUDE_PATHS)
	file(GLOB FILES RELATIVE "${CMAKE_SOURCE_DIR}" CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/${DIR}/*")
	set(DEST_DIR "${CMAKE_BINARY_DIR}/${DIR}")
	unset(RULES)
	unset(FILES_TO_COPY)
	unset(FILES_COPIED)
	unset(ALL_COPIED_FILES)

	execute_process(COMMAND ${CMAKE_COMMAND} "-E" "make_directory" ${DEST_DIR})

	foreach(FILE ${FILES})
		if (NOT FILE IN_LIST EXCLUDE_PATHS)
			set(SRC "${CMAKE_SOURCE_DIR}/${FILE}")
			set(DST "${CMAKE_BINARY_DIR}/${FILE}")
			if(IS_DIRECTORY ${SRC})
				copy_source_directory_to_output("${FILE}" "${EXCLUDE_PATHS}")
				list(APPEND RULES ${NEW_RULES})
				list(APPEND ALL_COPIED_FILES ${NEW_FILES})
			else()
				list(APPEND FILES_COPIED ${DST})
				if (SGXLKL_COPY_INDIVIDUAL_FILES)
					add_custom_command(OUTPUT ${DST}
						COMMAND ${CMAKE_COMMAND} "-E" "copy_if_different" ${SRC} "${DEST_DIR}"
						DEPENDS ${SRC}
						COMMENT "Copying LKL source ${SRC}")
				else()
					list(APPEND FILES_TO_COPY ${SRC})
				endif()
			endif()
		endif()
	endforeach()

	string(REPLACE "/" "_" RULE_NAME ${DIR})
	set(RULE_NAME "copy-files-${RULE_NAME}")

	if(FILES_TO_COPY)
		# Create the target directory at configure time, it won't change
		# Create a rule to copy the sources.  Ideally, we'd create one rule per
		# file, but CMake can't handle generating 65K rules, so instead we
		# generate one per directory
		add_custom_target(${RULE_NAME} 
			COMMAND ${CMAKE_COMMAND} "-E" "copy_if_different" ${FILES_TO_COPY} "${DEST_DIR}"
			DEPENDS ${FILES_TO_COPY}
			BYPRODUCTS ${FILES_COPIED}
			COMMENT "Copying LKL source directory ${DIR}")
		list(APPEND RULES ${RULE_NAME})
	endif()
	set(NEW_RULES ${RULES} PARENT_SCOPE)
	list(APPEND ALL_COPIED_FILES ${FILES_COPIED})
	set(NEW_FILES ${ALL_COPIED_FILES} PARENT_SCOPE)
endfunction()

