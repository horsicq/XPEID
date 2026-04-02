include_directories(${CMAKE_CURRENT_LIST_DIR})

if (NOT DEFINED XSCANENGINE_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XScanEngine/xscanengine.cmake)
    set(XPEID_SOURCES ${XPEID_SOURCES} ${XSCANENGINE_SOURCES})
endif()

set(XPEID_SOURCES
    ${XPEID_SOURCES}
    ${XSCANENGINE_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xpeid.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xpeid.h
)

get_property(_xpeid_install_registered GLOBAL PROPERTY XPEID_INSTALL_REGISTERED)
if(NOT _xpeid_install_registered)
    if(COMMAND deploy_install_directory)
        deploy_install_directory(
            SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/peid"
            INSTALL_DESTINATION peid
            WINDOWS_APPDATA_SUBDIR "${PROJECT_NAME}"
        )
    endif()

    set_property(GLOBAL PROPERTY XPEID_INSTALL_REGISTERED TRUE)
endif()
