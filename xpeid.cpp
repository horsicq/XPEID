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

XPEID::XPEID(QObject *pParent) : XScanEngine(pParent)
{
}

XPEID::XPEID(const XPEID &other) : XScanEngine(other)
{
    m_listSignatures = other.m_listSignatures;
}

QList<XPEID::SIGNATURE_RECORD> XPEID::getSignatures() const
{
    return m_listSignatures;
}

QString XPEID::getEngineName()
{
    return QString("PEiD");
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

bool XPEID::loadDatabase(const QString &sDatabasePath, XBinary::PDSTRUCT *pPdStruct)
{
    m_listSignatures.clear();

    QString sPath = sDatabasePath;

    QFileInfo fi(sPath);
    if (fi.isDir()) {
        QString sCandidate = QDir(sPath).filePath("userdb.txt");
        if (QFileInfo::exists(sCandidate)) {
            sPath = sCandidate;
        }
    }

    if (!QFileInfo::exists(sPath)) {
        return false;
    }

    QFile file(sPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream stream(&file);
    QString sLine;
    QString sSection;

    while (!stream.atEnd()) {
        sLine = stream.readLine();
        if (sLine.trimmed().isEmpty()) {
            continue;
        }

        if (_isUserDBComment(sLine)) {
            continue;
        }

        if (sLine.startsWith("[")) {
            // Section header: [something]
            int nPos = sLine.indexOf("]");
            if (nPos != -1) {
                sSection = sLine.mid(1, nPos - 1).trimmed();
            }
            continue;
        }

        // Typical PEiD signature line: <name> <hex pattern> [; comment]
        QString sClean = sLine;
        int nCommentPos = sClean.indexOf(";");
        if (nCommentPos >= 0) {
            sClean = sClean.left(nCommentPos);
        }
        sClean = sClean.trimmed();
        if (sClean.isEmpty()) {
            continue;
        }

        // Split first token as name, rest is signature pattern
        QStringList parts = sClean.split(QRegExp("\\s+"), Qt::SkipEmptyParts);
        if (parts.count() < 2) {
            continue;
        }

        QString sName = parts.takeFirst();
        QString sType = sSection;

        QString sSignature = parts.join(" ");
        sSignature = _normalizeSignature(sSignature);

        if (sSignature.isEmpty()) {
            continue;
        }

        SIGNATURE_RECORD record = {};
        record.sName = sName;
        record.sSignature = sSignature;
        record.sType = sType;
        record.sDescription = QString();

        m_listSignatures.append(record);
    }

    file.close();

    return (m_listSignatures.count() > 0);
}

void XPEID::_processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const SCANID &parentId,
                            XBinary::FT fileType, XScanEngine::SCAN_OPTIONS *pOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(fileType)
    Q_UNUSED(bAddUnknown)

    if (!pScanResult) {
        return;
    }

    if (m_listSignatures.isEmpty()) {
        return;
    }

    XBinary binary(pDevice);
    XBinary::_MEMORY_MAP memoryMap = binary.getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
    qint64 nSize = memoryMap.nBinarySize;

    XScanEngine::SCANID resultId = {};
    resultId.sUuid = XBinary::generateUUID();
    resultId.fileType = fileType;
    resultId.filePart = XBinary::FILEPART_HEADER;
    resultId.nSize = nSize;

    for (qint32 i = 0; i < m_listSignatures.count(); i++) {
        if (XBinary::isPdStructNotCanceled(pPdStruct)) {
            const SIGNATURE_RECORD &signature = m_listSignatures.at(i);

            if (binary.isSignaturePresent(&memoryMap, 0, nSize, signature.sSignature, pPdStruct)) {
                XScanEngine::SCANSTRUCT ss = {};
                ss.id = resultId;
                ss.parentId = parentId;
                ss.type = XScanEngine::RECORD_TYPE_PETOOL;
                ss.name = XScanEngine::RECORD_NAME_UNKNOWN;
                ss.sType = QString("PEiD");
                ss.sName = signature.sName;
                ss.sVersion = QString();
                ss.sInfo = signature.sType;
                ss.varInfo = signature.sSignature;
                ss.bIsUnknown = false;
                ss.bIsHeuristic = false;
                ss.bIsAHeuristic = false;

                pScanResult->listRecords.append(ss);
            }
        }
    }

    if (pScanID) {
        *pScanID = resultId;
    }
}
