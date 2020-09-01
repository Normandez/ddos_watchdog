cmake_minimum_required (VERSION 3.4.3)
project (ddos_watchdog CXX C)

set (VERSION_MAJOR 1)
set (VERSION_MINOR 0)
set (VERSION_PATCH 0)
set (VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

set (CMAKE_C_STANDARD 99)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_C_EXTENSIONS ON)

set (CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include (GNUInstallDirs)
include (${CMAKE_MODULE_PATH}/include_libraries.cmake)

set (INSTALL_SUFFIX "${CMAKE_PROJECT_NAME}")

string(APPEND CMAKE_C_FLAGS " ${EXTRA_C_FLAGS}")
string(APPEND CMAKE_CXX_FLAGS " ${EXTRA_CXX_FLAGS}")
string(APPEND CMAKE_EXE_LINKER_FLAGS " ${EXTRA_LINKER_FLAGS}")
string(APPEND CMAKE_MODULE_LINKER_FLAGS " ${EXTRA_LINKER_FLAGS}")

add_subdirectory (src)

message("
-------------------------------------------------------
${CMAKE_PROJECT_NAME} version ${VERSION}

Install options:
    prefix:     ${CMAKE_INSTALL_PREFIX}

Compiler options:
    CC:             ${CMAKE_C_COMPILER}
    CXX:            ${CMAKE_CXX_COMPILER}
    CFLAGS:         ${CMAKE_C_FLAGS}
    CXXFLAGS:       ${CMAKE_CXX_FLAGS}
    EXE_LDFLAGS:    ${CMAKE_EXE_LINKER_FLAGS}
    MODULE_LDFLAGS: ${CMAKE_MODULE_LINKER_FLAGS}
")

