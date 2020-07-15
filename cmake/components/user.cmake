include(cmake/Helpers.cmake)

touch("dummy.c")
add_library(sgxlkl_user_init STATIC "dummy.c")
target_link_libraries(sgxlkl_user_init PRIVATE
	sgx-lkl::libc-init
	curl::curl
	devicemapper::devicemapper
	e2fsprogs::ext2fs
)
add_library(sgx-lkl::user-init ALIAS sgxlkl_user_init)

set(SGXLKL_USER_OBJ "libsgxlkl_user.o")
add_custom_command(
	OUTPUT "${SGXLKL_USER_OBJ}"
	COMMENT "Building user space object"
	COMMAND "${LINKER}" -r -o "${SGXLKL_USER_OBJ}" --whole-archive
		$<TARGET_FILE:sgx-lkl::user-init>
	# TODO enable again, see notes above
	#COMMAND echo "Checking for unresolved symbols"
	#COMMAND ! "${CMAKE_NM}" -g "${SGXLKL_USER_OBJ}" | grep ' U '
	#| grep -v -E -e "'__(fini|init)_array_(start|end)'" # available at final link only
	#COMMAND echo "Hiding symbols"
	#COMMAND "${CMAKE_OBJCOPY}" --keep-global-symbol=lkl_syscall "${SGXLKL_USER_OBJ}"
	COMMAND_EXPAND_LISTS
	DEPENDS
		sgx-lkl::user-init
	)

add_library(sgx-lkl::user OBJECT IMPORTED GLOBAL)
set_target_properties(sgx-lkl::user PROPERTIES IMPORTED_OBJECTS "${SGXLKL_USER_OBJ}")
