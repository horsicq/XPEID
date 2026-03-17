# This CMake fragment is intended to be included from higher-level CMakeLists.txt files.
# It defines sources for building XPEID scan engine.

set(XPEID_SOURCES
    ${XPEID_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xpeid.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xpeid.h
)
