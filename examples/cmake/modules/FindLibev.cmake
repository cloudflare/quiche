# - Try to find libev
# Once done this will define
#  LIBEV_FOUND        - System has libev
#  LIBEV_INCLUDE_DIRS - The libev include directories
#  LIBEV_LIBRARIES    - The libraries needed to use libev

find_path(LIBEV_INCLUDE_DIR
  NAMES ev.h
)
find_library(LIBEV_LIBRARY
  NAMES ev
)

if(LIBEV_INCLUDE_DIR)
  file(STRINGS "${LIBEV_INCLUDE_DIR}/ev.h"
    LIBEV_VERSION_MAJOR REGEX "^#define[ \t]+EV_VERSION_MAJOR[ \t]+[0-9]+")
  file(STRINGS "${LIBEV_INCLUDE_DIR}/ev.h"
    LIBEV_VERSION_MINOR REGEX "^#define[ \t]+EV_VERSION_MINOR[ \t]+[0-9]+")
  string(REGEX REPLACE "[^0-9]+" "" LIBEV_VERSION_MAJOR "${LIBEV_VERSION_MAJOR}")
  string(REGEX REPLACE "[^0-9]+" "" LIBEV_VERSION_MINOR "${LIBEV_VERSION_MINOR}")
  set(LIBEV_VERSION "${LIBEV_VERSION_MAJOR}.${LIBEV_VERSION_MINOR}")
  unset(LIBEV_VERSION_MINOR)
  unset(LIBEV_VERSION_MAJOR)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBEV_FOUND to TRUE
# if all listed variables are TRUE and the requested version matches.
find_package_handle_standard_args(Libev REQUIRED_VARS
                                  LIBEV_LIBRARY LIBEV_INCLUDE_DIR
                                  VERSION_VAR LIBEV_VERSION)

if(LIBEV_FOUND)
  set(LIBEV_LIBRARIES     ${LIBEV_LIBRARY})
  set(LIBEV_INCLUDE_DIRS  ${LIBEV_INCLUDE_DIR})
endif()

mark_as_advanced(LIBEV_INCLUDE_DIR LIBEV_LIBRARY)
