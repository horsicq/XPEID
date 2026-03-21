cmake_minimum_required(VERSION 3.14)
project(XPEID)

# Qt is optional for configuration; the build will require Qt core headers and libraries to compile successfully.
find_package(Qt5 COMPONENTS Core Concurrent QUIET)

add_library(XPEID STATIC
    xpeid.cpp
    xpeid.h
)

target_include_directories(XPEID PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../XScanEngine
    ${CMAKE_CURRENT_LIST_DIR}/../XScanEngine/modules
    ${CMAKE_CURRENT_LIST_DIR}/../Formats
    ${CMAKE_CURRENT_LIST_DIR}/../Formats/exec
    ${CMAKE_CURRENT_LIST_DIR}/../Formats/formats
    ${CMAKE_CURRENT_LIST_DIR}/../Formats/images
    ${CMAKE_CURRENT_LIST_DIR}/../Formats/audio
    ${CMAKE_CURRENT_LIST_DIR}/../Formats/video
    ${CMAKE_CURRENT_LIST_DIR}/../Formats/texts
    ${CMAKE_CURRENT_LIST_DIR}/../XArchive
)

if (Qt5Core_FOUND)
    target_link_libraries(XPEID PUBLIC Qt5::Core)
endif()
if (Qt5Concurrent_FOUND)
    target_link_libraries(XPEID PUBLIC Qt5::Concurrent)
endif()

# Provide the list of sources for projects that collect sources into a single target.
set(XPEID_SOURCES ${XPEID_SOURCES} ${CMAKE_CURRENT_LIST_DIR}/xpeid.cpp ${CMAKE_CURRENT_LIST_DIR}/xpeid.h PARENT_SCOPE)
