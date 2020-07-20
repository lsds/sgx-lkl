include_guard(GLOBAL)

include(ExternalProject)
include(cmake/Constants.cmake)
include(cmake/components/common.cmake)

set(CFLAGS
  ${THIRD_PARTY_USERSPACE_CFLAGS}
  -Dptrdiff_t=intptr_t
)
list(JOIN CFLAGS " " CFLAGS)

set(EXTRA_OPTS)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(EXTRA_OPTS "--enable-debug")
endif()

# libdevmapper is used in userspace as dependency of libvicsetup.
ExternalProject_Add(devicemapper-ep
  URL ${DEVICEMAPPER_URL}
  URL_HASH ${DEVICEMAPPER_HASH}
  CONFIGURE_COMMAND "<SOURCE_DIR>/configure" 
    "CC=${CMAKE_C_COMPILER}"
    "CFLAGS=${CFLAGS}"
    "--enable-static_link"
    "--prefix=<INSTALL_DIR>"
    "${EXTRA_OPTS}"
  BUILD_COMMAND make -j ${NUMBER_OF_CORES} device-mapper
  INSTALL_COMMAND make -C <BINARY_DIR>/libdm install
  BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libdevmapper.a"
  DEPENDS ${THIRD_PARTY_USERSPACE_DEPENDS}
  ${COMMON_EP_OPTIONS}
)
ExternalProject_Get_property(devicemapper-ep INSTALL_DIR)
add_library(devicemapper INTERFACE)
target_link_libraries(devicemapper INTERFACE "${INSTALL_DIR}/lib/libdevmapper.a")
target_include_directories(devicemapper INTERFACE "${INSTALL_DIR}/include")
add_dependencies(devicemapper devicemapper-ep)
add_library(devicemapper::devicemapper ALIAS devicemapper)
