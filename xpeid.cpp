/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "xpeid.h"

#include "xbinary.h"
#include <QFile>
#include <QTextStream>
#include <QElapsedTimer>
#include <QtConcurrent/QtConcurrent>

XPEID::XPEID(QObject *pParent) : XScanEngine(pParent)
{
}

QString XPEID::getEngineName()
{
    return QString("PEiD");
}

XScanEngine::SCANENGINETYPE XPEID::getEngineType()
{
    return SCANENGINETYPE_PEID;
}

static bool _isUserDBComment(const QString &sLine)
{
    QString s = sLine.trimmed();
    return s.startsWith(";") || s.startsWith("#") || s.startsWith("//");
}

static QString _normalizeSignature(const QString &sSignature)
{
    // Convert to XBinary signature format: spaces removed, '?' -> '.', lowercased.
    return XBinary::convertSignature(sSignature);
}

static QString _getTypeFromFileName(const QString &sFilePath)
{
    QString sFileName = QFileInfo(sFilePath).fileName().toLower();

    if (sFileName.startsWith("compiler")) return QString("Compiler");
    if (sFileName.startsWith("packer")) return QString("Packer");
    if (sFileName.startsWith("protector")) return QString("Protector");
    if (sFileName.startsWith("protection")) return QString("Protection");
    if (sFileName.startsWith("crypter")) return QString("Crypter");
    if (sFileName.startsWith("installer")) return QString("Installer");
    if (sFileName.startsWith("joiner")) return QString("Joiner");
    if (sFileName.startsWith("archive")) return QString("Archive");
    if (sFileName.startsWith("overlay")) return QString("Overlay");
    if (sFileName.startsWith("sfx")) return QString("SFX");

    return QString("Unknown");
}

bool XPEID::isSignatureFileValid(const QString &sSignatureFilePath)
{
    bool bResult = false;

    QFileInfo fileInfo(sSignatureFilePath);

    if (fileInfo.isFile()) {
        bResult = sSignatureFilePath.endsWith(".userdb.txt", Qt::CaseInsensitive);
    }

    return bResult;
}

QList<XScanEngine::SIGNATURE_RECORD> XPEID::getSignaturesFromData(const QString &sData, const QString &sSignatureFilePath, XBinary::FT fileType,
                                                                  XBinary::PDSTRUCT *pPdStruct)
{
    QList<SIGNATURE_RECORD> listResult;

    QString sType = _getTypeFromFileName(sSignatureFilePath);

    QStringList listLines = sData.split("\n");
    qint32 nNumberOfLines = listLines.count();

    QString sCurrentName;
    QString sCurrentVersion;
    QString sCurrentInfo;
    QString sCurrentSignature;
    bool bCurrentEpOnly = true;
    qint64 nCurrentLine = 0;

    for (qint32 i = 0; (i < nNumberOfLines) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        QString sLine = listLines.at(i).trimmed();

        if (sLine.isEmpty()) {
            continue;
        }

        if (_isUserDBComment(sLine)) {
            continue;
        }

        if (sLine.startsWith("[")) {
            // Finalize previous entry
            if (!sCurrentName.isEmpty() && !sCurrentSignature.isEmpty()) {
                SIGNATURE_RECORD record = {};
                record.fileType = fileType;
                record.sFilePath = sSignatureFilePath;
                record.sType = sType;
                record.sName = sCurrentName;
                record.sVersion = sCurrentVersion;
                record.sInfo = sCurrentInfo;
                record.sText = _normalizeSignature(sCurrentSignature);
                record.bIsEP = bCurrentEpOnly;
                record.nLine = nCurrentLine;

                listResult.append(record);
            }

            // Start new entry
            nCurrentLine = i + 1;
            qint32 nPos = sLine.indexOf("]");
            if (nPos != -1) {
                sCurrentName = sLine.mid(1, nPos - 1).trimmed();
            } else {
                sCurrentName = sLine.mid(1).trimmed();
            }
            // [!EP (ExE Pack) V1.0 -> Elite Coding Group]
            sCurrentVersion.clear();
            sCurrentInfo.clear();
            qint32 nArrowPos = sCurrentName.indexOf("->");
            if (nArrowPos != -1) {
                sCurrentInfo = sCurrentName.mid(nArrowPos + 2).trimmed();
                sCurrentName = sCurrentName.left(nArrowPos).trimmed();
            }
            // Extract version: first token starting with V/v+digit or a bare digit
            {
                qint32 nVersionPos = -1;
                qint32 nNameLen = sCurrentName.length();
                for (qint32 j = 0; j < nNameLen;) {
                    while (j < nNameLen && sCurrentName.at(j) == QChar(' ')) {
                        j++;
                    }
                    if (j >= nNameLen) {
                        break;
                    }
                    QChar cFirst = sCurrentName.at(j);
                    bool bIsVersion = false;
                    if ((cFirst == QChar('v') || cFirst == QChar('V')) && (j + 1 < nNameLen) && sCurrentName.at(j + 1).isDigit()) {
                        bIsVersion = true;
                    } else if (cFirst.isDigit()) {
                        bIsVersion = true;
                    }
                    if (bIsVersion && j > 0) {
                        nVersionPos = j;
                        break;
                    }
                    while (j < nNameLen && sCurrentName.at(j) != QChar(' ')) {
                        j++;
                    }
                }
                if (nVersionPos != -1) {
                    sCurrentVersion = sCurrentName.mid(nVersionPos).trimmed();
                    sCurrentName = sCurrentName.left(nVersionPos).trimmed();
                }
            }

            sCurrentSignature.clear();
            bCurrentEpOnly = true;
            continue;
        }

        if (sLine.startsWith("signature", Qt::CaseInsensitive)) {
            qint32 nEqPos = sLine.indexOf("=");

            if (nEqPos != -1) {
                sCurrentSignature = sLine.mid(nEqPos + 1).trimmed();
            }

            continue;
        }

        if (sLine.startsWith("ep_only", Qt::CaseInsensitive)) {
            qint32 nEqPos = sLine.indexOf("=");

            if (nEqPos != -1) {
                QString sValue = sLine.mid(nEqPos + 1).trimmed().toLower();
                bCurrentEpOnly = (sValue == "true");
            }

            continue;
        }
    }

    // Finalize last entry
    if (!sCurrentName.isEmpty() && !sCurrentSignature.isEmpty()) {
        SIGNATURE_RECORD record = {};
        record.fileType = fileType;
        record.sFilePath = sSignatureFilePath;
        record.sType = sType;
        record.sName = sCurrentName;
        record.sVersion = sCurrentVersion;
        record.sInfo = sCurrentInfo;
        record.sText = _normalizeSignature(sCurrentSignature);
        record.bIsEP = bCurrentEpOnly;
        record.nLine = nCurrentLine;

        listResult.append(record);
    }

    return listResult;
}

struct _XPEID_SCAN_CONTEXT {
    const QList<XScanEngine::SIGNATURE_RECORD> *pListSignatures;
    const QByteArray *pbaData;
    qint64 nSize;
    XScanEngine::SCANID resultId;
    XScanEngine::SCANID parentId;
    QList<XScanEngine::SCANSTRUCT> *pListMatches;
    QList<XScanEngine::DEBUG_RECORD> *pListDebugRecords;
    QMutex *pMutex;
    XBinary::PDSTRUCT *pPdStruct;
    qint32 nFreeIndex;
    bool bShowScanTime;

    void operator()(const qint32 &nIndex)
    {
        if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
            return;
        }

        const XScanEngine::SIGNATURE_RECORD &signature = pListSignatures->at(nIndex);

        QElapsedTimer elapsedTimer;
        elapsedTimer.start();

        QBuffer buffer;
        buffer.setData(*pbaData);
        buffer.open(QIODevice::ReadOnly);

        XBinary bin(&buffer);
        XBinary::_MEMORY_MAP mm = bin.getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);

        bool bMatch = bin.isSignaturePresent(&mm, 0, nSize, signature.sText, pPdStruct);

        qint64 nElapsedTime = elapsedTimer.elapsed();

        if (bMatch) {
            XScanEngine::SCANSTRUCT ss = {};
            ss.id = resultId;
            ss.parentId = parentId;
            ss.sType = signature.sType;
            ss.sName = signature.sName;
            ss.type = XScanEngine::recordTypeStringToId(signature.sType);
            ss.name = XScanEngine::recordNameStringToId(signature.sName);
            ss.sVersion = signature.sVersion;
            ss.sInfo = signature.sInfo;
            ss.bIsUnknown = false;
            ss.bIsHeuristic = false;
            ss.bIsAHeuristic = false;

            QMutexLocker locker(pMutex);
            pListMatches->append(ss);
        }

        {
            QMutexLocker locker(pMutex);

            if (bShowScanTime) {
                XScanEngine::DEBUG_RECORD debugRecord = {};
                debugRecord.sScript = signature.sName;
                debugRecord.sType = signature.sType;
                debugRecord.sName = signature.sName;
                debugRecord.nElapsedTime = nElapsedTime;
                debugRecord.nLine = signature.nLine;
                pListDebugRecords->append(debugRecord);
            }

            XBinary::setPdStructCurrentIncrement(pPdStruct, nFreeIndex);
        }
    }
};

void XPEID::_processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const SCANID &parentId, XBinary::FT fileType,
                           XScanEngine::SCAN_OPTIONS *pOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pScanResult) {
        return;
    }

    if (m_listSignatures.isEmpty()) {
        return;
    }

    XBinary binary(pDevice);
    XBinary::_MEMORY_MAP memoryMap = binary.getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
    qint64 nSize = memoryMap.nBinarySize;

    qint32 nNumberOfSignatures = m_listSignatures.count();

    // Separate EP and non-EP signature indices, filtered by fileType
    QList<qint32> listEpIndices;
    QList<qint32> listNonEpIndices;
    qint32 nMaxEpSigBytes = 0;

    for (qint32 i = 0; i < nNumberOfSignatures; i++) {
        const SIGNATURE_RECORD &sig = m_listSignatures.at(i);

        if (!XBinary::checkFileType(sig.fileType, fileType)) {
            continue;
        }

        if (sig.bIsEP) {
            listEpIndices.append(i);
            qint32 nSigBytes = sig.sText.length() / 2;

            if (nSigBytes > nMaxEpSigBytes) {
                nMaxEpSigBytes = nSigBytes;
            }
        } else {
            listNonEpIndices.append(i);
        }
    }

    // Get entry point offset and read EP signature once
    qint64 nEpOffset = XFormats::getEntryPointOffset(fileType, pDevice);
    QString sEpSignature;

    if ((nMaxEpSigBytes > 0) && (nEpOffset >= 0) && (nEpOffset < nSize)) {
        sEpSignature = binary.getSignature(nEpOffset, nMaxEpSigBytes).toLower();
    }

    XScanEngine::SCANID resultId = {};
    resultId.sUuid = XBinary::generateUUID();
    resultId.fileType = fileType;
    resultId.filePart = parentId.filePart;
    resultId.nSize = nSize;

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfSignatures);

    // Phase 1: EP signatures (fast string compare, sequential)
    for (qint32 i = 0; (i < listEpIndices.count()) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        const SIGNATURE_RECORD &signature = m_listSignatures.at(listEpIndices.at(i));

        QElapsedTimer elapsedTimer;
        elapsedTimer.start();

        bool bMatch = false;

        if (!sEpSignature.isEmpty()) {
            bMatch = XBinary::compareSignatureStrings(sEpSignature, signature.sText);
        }

        qint64 nElapsedTime = elapsedTimer.elapsed();

        if (bMatch) {
            XScanEngine::SCANSTRUCT ss = {};
            ss.id = resultId;
            ss.parentId = parentId;
            ss.sType = signature.sType;
            ss.sName = signature.sName;
            ss.type = XScanEngine::recordTypeStringToId(signature.sType);
            ss.name = XScanEngine::recordNameStringToId(signature.sName);
            ss.sVersion = signature.sVersion;
            ss.sInfo = signature.sInfo;
            ss.bIsUnknown = false;
            ss.bIsHeuristic = false;
            ss.bIsAHeuristic = false;

            pScanResult->listRecords.append(ss);
        }

        if (pOptions->bShowScanTime) {
            XScanEngine::DEBUG_RECORD debugRecord = {};
            debugRecord.sScript = signature.sName;
            debugRecord.sType = signature.sType;
            debugRecord.sName = signature.sName;
            debugRecord.nElapsedTime = nElapsedTime;
            debugRecord.nLine = signature.nLine;
            pScanResult->listDebugRecords.append(debugRecord);
        }

        XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
    }

    // Phase 2: Non-EP signatures in parallel (scan through file data)
    if (!listNonEpIndices.isEmpty() && XBinary::isPdStructNotCanceled(pPdStruct)) {
        QByteArray baData = binary.read_array(0, nSize);
        QMutex mutex;
        QList<XScanEngine::SCANSTRUCT> listMatches;
        QList<XScanEngine::DEBUG_RECORD> listDebugRecords;

        _XPEID_SCAN_CONTEXT context = {};
        context.pListSignatures = &m_listSignatures;
        context.pbaData = &baData;
        context.nSize = nSize;
        context.resultId = resultId;
        context.parentId = parentId;
        context.pListMatches = &listMatches;
        context.pListDebugRecords = &listDebugRecords;
        context.pMutex = &mutex;
        context.pPdStruct = pPdStruct;
        context.nFreeIndex = _nFreeIndex;
        context.bShowScanTime = pOptions->bShowScanTime;

        QtConcurrent::blockingMap(listNonEpIndices, context);

        pScanResult->listRecords.append(listMatches);
        pScanResult->listDebugRecords.append(listDebugRecords);
    }

    XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);

    if (bAddUnknown && pScanResult->listRecords.isEmpty()) {
        XScanEngine::SCANSTRUCT ss = {};
        ss.id = resultId;
        ss.parentId = parentId;
        ss.sType = XScanEngine::recordTypeIdToString(XScanEngine::RECORD_TYPE_UNKNOWN);
        ss.type = XScanEngine::RECORD_TYPE_UNKNOWN;
        ss.name = XScanEngine::RECORD_NAME_UNKNOWN;
        ss.bIsUnknown = true;
        ss.bIsHeuristic = false;
        ss.bIsAHeuristic = false;

        pScanResult->listRecords.append(ss);
    }

    if (pScanID) {
        *pScanID = resultId;
    }
}
