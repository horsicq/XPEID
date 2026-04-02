INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

QT += concurrent

!contains(XCONFIG, xscanengine) {
    XCONFIG += xscanengine
    include($$PWD/../XScanEngine/xscanengine.pri)
}

HEADERS += \
    $$PWD/xpeid.h

SOURCES += \
    $$PWD/xpeid.cpp
