INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xpeid.h

SOURCES += \
    $$PWD/xpeid.cpp

!contains(XCONFIG, xscanengine) {
    XCONFIG += xscanengine
    include($$PWD/../XScanEngine/xscanengine.pri)
}
