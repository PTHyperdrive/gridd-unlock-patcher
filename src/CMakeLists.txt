# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.5)

project(gridd-unlock-patcher CXX)

include(ExternalProject)
include(cmake/FetchCPM.cmake)

CPMAddPackage(
        NAME LIEF_SRC
        GITHUB_REPOSITORY lief-project/LIEF
        GIT_TAG 0.16.4
        DOWNLOAD_ONLY YES
)

if (LIEF_SRC_ADDED)
    set(LIEF_PREFIX       "${CMAKE_CURRENT_BINARY_DIR}/LIEF")
    set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
    set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include")

    set(LIEF_LIBRARIES
            "${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}"
    )

    set(LIEF_CMAKE_ARGS
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
            -DLIEF_EXAMPLES=off
            -DLIEF_ENABLE_JSON=off
            -DLIEF_MACHO=off
            -DLIEF_DEX=off
    )

    ExternalProject_Add(LIEF
            PREFIX           "${LIEF_PREFIX}"
            SOURCE_DIR       ${LIEF_SRC_SOURCE_DIR}
            INSTALL_DIR      ${LIEF_INSTALL_DIR}
            CMAKE_ARGS       ${LIEF_CMAKE_ARGS}
            BUILD_BYPRODUCTS ${LIEF_LIBRARIES}
            UPDATE_COMMAND   ""
    )
endif()

message(STATUS "LIEF include directory: ${LIEF_INCLUDE_DIRS}")
message(STATUS "LIEF library: ${LIEF_LIBRARIES}")

add_executable(gridd-unlock-patcher gridd-unlock-patcher.cpp)

add_dependencies(gridd-unlock-patcher LIEF)

target_include_directories(gridd-unlock-patcher PRIVATE ${LIEF_INCLUDE_DIRS})
target_link_libraries(gridd-unlock-patcher PRIVATE ${LIEF_LIBRARIES})

set_target_properties(gridd-unlock-patcher PROPERTIES LINK_FLAGS_RELEASE -s)
install(TARGETS gridd-unlock-patcher)
