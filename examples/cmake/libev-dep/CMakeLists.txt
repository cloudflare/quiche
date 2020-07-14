# Download and build libev for use on Windows.
cmake_minimum_required(VERSION 3.0...3.17)
project(Libev LANGUAGES C)

set(BASENAME "libev-4.33")
file(DOWNLOAD
  http://dist.schmorp.de/libev/Attic/${BASENAME}.tar.gz
  ${CMAKE_CURRENT_BINARY_DIR}/${BASENAME}.tar.gz
  EXPECTED_HASH SHA256=507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea
)
execute_process(COMMAND "${CMAKE_COMMAND}" -E tar xzf ${BASENAME}.tar.gz
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Error unpacking libev")
endif()

add_library(ev "${BASENAME}/ev.c")
target_compile_definitions(ev PRIVATE EV_STANDALONE)
# Ensure that include and lib within the build dir are populated on Windows.
set_target_properties(ev PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY_DEBUG lib
  ARCHIVE_OUTPUT_DIRECTORY_RELEASE lib)
configure_file("${CMAKE_CURRENT_BINARY_DIR}/${BASENAME}/ev.h"
  "${CMAKE_CURRENT_BINARY_DIR}/include/ev.h" COPYONLY)
