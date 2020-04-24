include_guard(GLOBAL)

function(download_and_extract_tarball NAME URL)
	execute_process(COMMAND ${CMAKE_COMMAND} "-E" "make_directory" "${CMAKE_BINARY_DIR}/downloads")
	set(TARFILE "${CMAKE_BINARY_DIR}/downloads/${NAME}.tar.gz")
	add_custom_command(OUTPUT ${TARFILE}
		COMMAND "wget" ARGS "-nv" "-O" "${TARFILE}" "'${URL}'"
		COMMENT "Downloading ${NAME}")
	set(DOTFILE ".extract-${NAME}")
	add_custom_command(OUTPUT ${DOTFILE}
		COMMAND ${CMAKE_COMMAND} ARGS "-E" "make_directory" "${THIRD_PARTY_DOWNLOADS_DIRECTORY}/${NAME}"
		COMMAND "tar" "-C" "${THIRD_PARTY_DOWNLOADS_DIRECTORY}/${NAME}" "--strip" "1" "-xf" ${TARFILE}
		COMMAND ${CMAKE_COMMAND} ARGS "-E" "touch" ${DOTFILE}
		DEPENDS ${TARFILE}
		COMMENT "Extracting ${NAME}")
	add_custom_target("fetch-and-extract-${NAME}" DEPENDS ${DOTFILE} COMMENT "Fetch and extract ${NAME}")
	set("${NAME}_LOCATION" "${THIRD_PARTY_DOWNLOADS_DIRECTORY}/${NAME}" PARENT_SCOPE)
endfunction(download_and_extract_tarball)
