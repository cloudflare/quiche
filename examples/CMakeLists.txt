if(WIN32)
  # target_link_options requires CMake 3.13
  cmake_minimum_required(VERSION 3.13...3.17)
else()
  cmake_minimum_required(VERSION 3.1...3.17)
endif()
project(QuicheExamples LANGUAGES C)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

# Default to a Debug build.
if(NOT DEFINED CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "None" "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

if(NOT CMAKE_C_FLAGS AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  set(CMAKE_C_FLAGS "-Wall -Werror -pedantic -fsanitize=address")
endif()

if(MSVC AND CMAKE_GENERATOR_PLATFORM STREQUAL x64)
  set(CARGO_TARGET x86_64-pc-windows-msvc)
elseif(MSVC AND CMAKE_GENERATOR_PLATFORM STREQUAL Win32)
  set(CARGO_TARGET i686-pc-windows-msvc)
endif()

set(BUILD_DIR       "${CMAKE_CURRENT_BINARY_DIR}/build")
set(QUICHE_LIBNAME  "${CMAKE_STATIC_LIBRARY_PREFIX}quiche${CMAKE_STATIC_LIBRARY_SUFFIX}")
if(CARGO_TARGET)
  set(CARGO_OPTS --target=${CARGO_TARGET})
  set(QUICHE_LIB  "${BUILD_DIR}/${CARGO_TARGET}/debug/${QUICHE_LIBNAME}")
else()
  set(QUICHE_LIB  "${BUILD_DIR}/debug/${QUICHE_LIBNAME}")
endif()

# Remove quiche build directory as part of the 'clean' target
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES "${BUILD_DIR}")

# Add target to build quiche when any of its sources have changed.
file(GLOB_RECURSE QUICHE_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/../src/*.rs")
add_custom_target(quiche-build DEPENDS "${QUICHE_LIB}")
add_custom_command(OUTPUT "${QUICHE_LIB}"
  COMMAND cargo build --target-dir "${BUILD_DIR}" ${CARGO_OPTS}
  DEPENDS ${QUICHE_SOURCES}
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  USES_TERMINAL
  VERBATIM)

# Since quiche is built outside CMake using cargo, it has to be imported for
# it to be usable by other objects. Additional header include paths and library
# linking dependencies are also configured here.
add_library(quiche STATIC IMPORTED)
set_target_properties(quiche PROPERTIES IMPORTED_LOCATION "${QUICHE_LIB}")
add_dependencies(quiche quiche-build)
target_include_directories(quiche INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
if(APPLE)
  # For SecRandomCopyBytes used by ring::rand::SystemRandom.
  set_target_properties(quiche PROPERTIES
    INTERFACE_LINK_LIBRARIES "-framework Security")
elseif(WIN32)
  # Crypt32 for CertOpenSystemStoreA used by src/tls.rs, Userenv for std::env,
  # Ws2_32 for getaddrinfo, Advapi32 for RtlGenRandom.
  set_target_properties(quiche PROPERTIES
    INTERFACE_LINK_LIBRARIES "Crypt32;Userenv;Ws2_32;Advapi32")
  # cc-rs up to at least 1.0.53 adds /MD which results in a LNK4098 warning
  # because CMake adds a conflicting /MDd option in debug mode. Ensure msvcrtd
  # is linked in Debug builds by skipping msvcrt (normally added via /MD).
  target_link_options(quiche INTERFACE "$<$<CONFIG:Debug>:/NODEFAULTLIB:msvcrt>")
endif()

# All examples require the external libev library. Server examples need uthash.
find_package(Libev REQUIRED)
include_directories(${LIBEV_INCLUDE_DIRS})

find_path(UTHASH_INCLUDE_DIR uthash.h)
if(UTHASH_INCLUDE_DIR)
  message(STATUS "Found uthash.h at ${UTHASH_INCLUDE_DIR}")
else()
  set(UTHASH_DL_DIR ${CMAKE_CURRENT_BINARY_DIR}/uthash/include)
  if(NOT EXISTS ${UTHASH_DL_DIR}/uthash.h)
    message(STATUS "Downloading uthash.h to ${UTHASH_DL_DIR}")
    file(DOWNLOAD
      https://raw.githubusercontent.com/troydhanson/uthash/v2.1.0/src/uthash.h
      ${UTHASH_DL_DIR}/uthash.h.tmp
      EXPECTED_HASH SHA256=ba9af0e8c902108cc40be8e742ff4fcbb0e93062d91aefd6070b70d4e067c2ac)
    file(RENAME ${UTHASH_DL_DIR}/uthash.h.tmp ${UTHASH_DL_DIR}/uthash.h)
  else()
    message(STATUS "Found uthash.h at ${UTHASH_DL_DIR}")
  endif()
  set(UTHASH_INCLUDE_DIR ${UTHASH_DL_DIR})
endif()

function(add_c_example name)
  add_executable(${name} ${name}.c)
  target_link_libraries(${name} quiche ${LIBEV_LIBRARIES} ${CMAKE_DL_LIBS})
  if(UNIX)
    target_link_libraries(${name} -pthread)
  endif()
endfunction()

add_c_example(client)
add_c_example(http3-client)
add_c_example(server)
target_include_directories(server PRIVATE "${UTHASH_INCLUDE_DIR}")
add_c_example(http3-server)
target_include_directories(http3-server PRIVATE "${UTHASH_INCLUDE_DIR}")
