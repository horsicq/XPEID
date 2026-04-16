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

#ifndef XPEID_H
#define XPEID_H

#include "xscanengine.h"

// Simple PEiD userdb.txt parser and scanner
class XPEID : public XScanEngine {
    Q_OBJECT

public:
    explicit XPEID(QObject *pParent = nullptr);

    virtual QString getEngineName() override;
    virtual SCANENGINETYPE getEngineType() override;
    virtual bool isSignatureFileValid(const QString &sSignatureFilePath) override;
    virtual QList<SIGNATURE_RECORD> getSignaturesFromData(const QString &sData, const QString &sSignatureFilePath, XBinary::FT fileType,
                                                          XBinary::PDSTRUCT *pPdStruct) override;
    virtual bool isDatabaseUsing();

protected:
    virtual void _processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const SCANID &parentId, XBinary::FT fileType,
                                XScanEngine::SCAN_OPTIONS *pOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct) override;
};

#endif  // XPEID_H
