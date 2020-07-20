include_guard(GLOBAL)
include(cmake/Helpers.cmake)
include(cmake/components/common.cmake)
include(cmake/components/curl.cmake)
include(cmake/components/devicemapper.cmake)
include(cmake/components/ext2fs.cmake)
include(cmake/components/json.cmake)

touch("dummy.c")
add_library(sgxlkl-user-init STATIC "dummy.c")
target_link_libraries(sgxlkl-user-init PRIVATE
  sgx-lkl::libc-init
  curl::curl
  devicemapper::devicemapper
  e2fsprogs::ext2fs
)
add_library(sgx-lkl::user-init ALIAS sgxlkl-user-init)

set(SGXLKL_USER_OBJ "${CMAKE_CURRENT_BINARY_DIR}/libsgxlkl-user.o")
add_custom_command(
  OUTPUT "${SGXLKL_USER_OBJ}"
  COMMENT "Building user space object"
  COMMAND "${LINKER}" -r -o "${SGXLKL_USER_OBJ}" 
    --whole-archive
    $<TARGET_FILE:sgx-lkl::user-init>
    $<TARGET_PROPERTY:sgx-lkl::libc-init,INTERFACE_LINK_LIBRARIES>
    --no-whole-archive
    ${C_COMPILER_RT_LIBRARY}
  COMMAND echo "Checking for unresolved symbols"
  COMMAND ! "${CMAKE_NM}" -g "${SGXLKL_USER_OBJ}" 
          | grep ' U ' # filter to undefined symbols
          | grep -v -E
              -e "'__(fini|init)_array_(start|end)'" # available at final link only	 
  # TODO how to whitelist libc symbols? is that really necessary?
  #COMMAND echo "Hiding symbols"
  #COMMAND "${CMAKE_OBJCOPY}" --keep-global-symbol=lkl_syscall "${SGXLKL_USER_OBJ}"
  COMMAND_EXPAND_LISTS
  DEPENDS sgx-lkl::user-init
  )

add_library(sgxlkl-user STATIC "${SGXLKL_USER_OBJ}")
set_target_properties(sgxlkl-user PROPERTIES LINKER_LANGUAGE C)
add_library(sgx-lkl::user ALIAS sgxlkl-user)