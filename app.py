from flask import Flask, request, render_template_string, jsonify
from PyPDF2 import PdfReader

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PMAT — PDF Malware Analysis Toolkit</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0e1a;
    --panel: #0f1629;
    --border: #1e2d4a;
    --accent: #00d4ff;
    --danger: #ff3860;
    --safe: #00e676;
    --warn: #ffab00;
    --text: #c8d8f0;
    --muted: #4a6080;
    --font-mono: 'Share Tech Mono', monospace;
    --font-main: 'Exo 2', sans-serif;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-main);
    min-height: 100vh;
    background-image:
      radial-gradient(ellipse at 20% 50%, rgba(0,212,255,0.04) 0%, transparent 60%),
      radial-gradient(ellipse at 80% 20%, rgba(255,56,96,0.04) 0%, transparent 60%);
  }

  .scanline {
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
    pointer-events: none; z-index: 0;
  }

  .container { max-width: 860px; margin: 0 auto; padding: 40px 20px; position: relative; z-index: 1; }

  header { text-align: center; margin-bottom: 40px; }

  .logo {
    font-family: var(--font-mono);
    font-size: clamp(28px, 5vw, 42px);
    color: var(--accent);
    letter-spacing: 4px;
    text-shadow: 0 0 30px rgba(0,212,255,0.5);
    animation: flicker 4s infinite;
  }

  @keyframes flicker {
    0%,95%,100% { opacity: 1; }
    96% { opacity: 0.85; }
    97% { opacity: 1; }
    98% { opacity: 0.9; }
  }

  .subtitle {
    font-size: 12px;
    letter-spacing: 6px;
    color: var(--muted);
    text-transform: uppercase;
    margin-top: 8px;
  }

  .badge {
    display: inline-block;
    background: rgba(255,56,96,0.15);
    border: 1px solid rgba(255,56,96,0.4);
    color: var(--danger);
    font-size: 10px;
    letter-spacing: 3px;
    padding: 3px 10px;
    border-radius: 2px;
    margin-top: 12px;
    font-family: var(--font-mono);
  }

  .upload-panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 40px;
    text-align: center;
    position: relative;
    overflow: hidden;
    transition: border-color 0.3s;
  }

  .upload-panel::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    animation: scan-line 3s linear infinite;
  }

  @keyframes scan-line {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(100%); }
  }

  .upload-panel.drag-over { border-color: var(--accent); }

  .upload-icon { font-size: 48px; margin-bottom: 16px; }

  .drop-text {
    font-size: 16px;
    color: var(--muted);
    margin-bottom: 24px;
    font-weight: 300;
  }

  .drop-text span { color: var(--accent); font-weight: 600; }

  #fileInput { display: none; }

  .file-label {
    display: inline-block;
    background: transparent;
    border: 1px solid var(--accent);
    color: var(--accent);
    padding: 12px 28px;
    border-radius: 4px;
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 13px;
    letter-spacing: 2px;
    transition: all 0.2s;
    margin-bottom: 12px;
  }

  .file-label:hover {
    background: rgba(0,212,255,0.1);
    box-shadow: 0 0 20px rgba(0,212,255,0.2);
  }

  #fileName {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--muted);
    margin: 10px 0;
    min-height: 20px;
  }

  .analyze-btn {
    display: block;
    width: 100%;
    margin-top: 20px;
    padding: 16px;
    background: linear-gradient(135deg, rgba(0,212,255,0.15), rgba(0,212,255,0.05));
    border: 1px solid var(--accent);
    color: var(--accent);
    font-family: var(--font-mono);
    font-size: 15px;
    letter-spacing: 4px;
    cursor: pointer;
    border-radius: 4px;
    transition: all 0.3s;
    text-transform: uppercase;
  }

  .analyze-btn:hover:not(:disabled) {
    background: rgba(0,212,255,0.2);
    box-shadow: 0 0 30px rgba(0,212,255,0.3);
    transform: translateY(-1px);
  }

  .analyze-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

  /* Loading */
  .loading-panel {
    display: none;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 30px;
    margin-top: 20px;
    text-align: center;
  }

  .progress-bar {
    height: 3px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
    margin: 16px 0;
  }

  .progress-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent), #0077ff);
    border-radius: 2px;
    animation: progress-anim 2s ease-in-out infinite;
  }

  @keyframes progress-anim {
    0% { width: 10%; margin-left: 0; }
    50% { width: 60%; margin-left: 20%; }
    100% { width: 10%; margin-left: 80%; }
  }

  .loading-steps { font-family: var(--font-mono); font-size: 12px; color: var(--muted); }
  .loading-step { padding: 4px 0; transition: color 0.3s; }
  .loading-step.active { color: var(--accent); }
  .loading-step.done { color: var(--safe); }

  /* Result */
  #result { margin-top: 24px; }

  .result-panel {
    background: var(--panel);
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid var(--border);
  }

  .result-header {
    padding: 24px 28px;
    display: flex;
    align-items: center;
    gap: 20px;
    border-bottom: 1px solid var(--border);
  }

  .verdict-badge {
    font-family: var(--font-mono);
    font-size: 13px;
    letter-spacing: 3px;
    padding: 8px 20px;
    border-radius: 4px;
    font-weight: 700;
    flex-shrink: 0;
  }

  .verdict-CLEAN    { background: rgba(0,230,118,0.15); border: 1px solid var(--safe);  color: var(--safe); }
  .verdict-LOW      { background: rgba(0,212,255,0.15); border: 1px solid var(--accent); color: var(--accent); }
  .verdict-MEDIUM   { background: rgba(255,171,0,0.15); border: 1px solid var(--warn);  color: var(--warn); }
  .verdict-HIGH     { background: rgba(255,56,96,0.12); border: 1px solid var(--danger); color: var(--danger); }
  .verdict-CRITICAL { background: rgba(255,56,96,0.2);  border: 1px solid var(--danger); color: var(--danger); box-shadow: 0 0 20px rgba(255,56,96,0.3); }

  .score-ring {
    width: 70px; height: 70px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-family: var(--font-mono);
    font-size: 22px;
    font-weight: 700;
    flex-shrink: 0;
    border: 3px solid;
  }

  .score-ring.low    { border-color: var(--safe);   color: var(--safe); }
  .score-ring.medium { border-color: var(--warn);   color: var(--warn); }
  .score-ring.high   { border-color: var(--danger); color: var(--danger); }

  .result-meta h2 { font-size: 18px; font-weight: 600; margin-bottom: 4px; }
  .result-meta p  { font-size: 12px; color: var(--muted); font-family: var(--font-mono); }

  .result-body { padding: 24px 28px; }

  .info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }

  .info-card {
    background: rgba(255,255,255,0.02);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px 16px;
  }

  .info-card label {
    display: block;
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 6px;
    font-family: var(--font-mono);
  }

  .info-card value {
    display: block;
    font-size: 14px;
    font-weight: 600;
    word-break: break-all;
  }

  .section-title {
    font-size: 11px;
    letter-spacing: 3px;
    color: var(--muted);
    text-transform: uppercase;
    font-family: var(--font-mono);
    margin: 20px 0 10px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }

  .ioc-list { list-style: none; }

  .ioc-item {
    display: flex; align-items: center; gap: 10px;
    padding: 8px 12px;
    background: rgba(255,56,96,0.05);
    border: 1px solid rgba(255,56,96,0.2);
    border-radius: 4px;
    margin-bottom: 6px;
    font-family: var(--font-mono);
    font-size: 12px;
    word-break: break-all;
  }

  .ioc-tag {
    font-size: 9px;
    letter-spacing: 2px;
    padding: 2px 7px;
    border-radius: 2px;
    flex-shrink: 0;
    background: rgba(255,56,96,0.2);
    color: var(--danger);
    border: 1px solid rgba(255,56,96,0.3);
  }

  .breakdown-item {
    display: flex; align-items: center; gap: 10px;
    padding: 6px 0;
    font-size: 13px;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    font-family: var(--font-mono);
    color: var(--muted);
  }

  .breakdown-item::before { content: '▶'; font-size: 8px; color: var(--accent); }

  .no-ioc {
    text-align: center; padding: 16px;
    color: var(--safe); font-family: var(--font-mono); font-size: 12px;
  }

  .error-panel {
    background: rgba(255,56,96,0.08);
    border: 1px solid rgba(255,56,96,0.3);
    border-radius: 8px;
    padding: 24px;
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--danger);
    margin-top: 20px;
  }

  footer {
    text-align: center;
    margin-top: 50px;
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 2px;
    font-family: var(--font-mono);
  }
</style>
</head>
<body>
<div class="scanline"></div>
<div class="container">

  <header>
    <div class="logo">[ PMAT ]</div>
    <div class="subtitle">PDF Malware Analysis Toolkit v1.0</div>
    <div class="badge">⚠ EDUCATIONAL USE ONLY ⚠</div>
  </header>

  <div class="upload-panel" id="dropZone">
    <div class="upload-icon">📄</div>
    <p class="drop-text">Drag & drop a PDF here or <span>browse to upload</span></p>
    <label class="file-label" for="fileInput">[ SELECT PDF FILE ]</label>
    <input type="file" id="fileInput" accept=".pdf">
    <div id="fileName">No file selected</div>
    <button class="analyze-btn" id="analyzeBtn" onclick="analyzePDF()" disabled>
      ▶ RUN ANALYSIS
    </button>
  </div>

  <div class="loading-panel" id="loadingPanel">
    <div style="font-family:var(--font-mono);font-size:14px;color:var(--accent);letter-spacing:3px;">ANALYZING...</div>
    <div class="progress-bar"><div class="progress-fill"></div></div>
    <div class="loading-steps">
      <div class="loading-step" id="s1">[ 1/8 ] Loading PDF & extracting file info</div>
      <div class="loading-step" id="s2">[ 2/8 ] Metadata extraction & anomaly detection</div>
      <div class="loading-step" id="s3">[ 3/8 ] Object enumeration & structure analysis</div>
      <div class="loading-step" id="s4">[ 4/8 ] Keyword-based threat detection</div>
      <div class="loading-step" id="s5">[ 5/8 ] Stream decoding & content extraction</div>
      <div class="loading-step" id="s6">[ 6/8 ] IOC extraction</div>
      <div class="loading-step" id="s7">[ 7/8 ] JavaScript analysis</div>
      <div class="loading-step" id="s8">[ 8/8 ] Risk scoring & report generation</div>
    </div>
  </div>

  <div id="result"></div>

  <footer>PMAT © 2025 — Cybersecurity Project | GEC Jamui</footer>
</div>

<script>
const fileInput = document.getElementById('fileInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const fileNameEl = document.getElementById('fileName');
const dropZone = document.getElementById('dropZone');

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) {
    fileNameEl.textContent = '📎 ' + fileInput.files[0].name;
    analyzeBtn.disabled = false;
  }
});

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f && f.name.endsWith('.pdf')) {
    fileInput.files = e.dataTransfer.files;
    fileNameEl.textContent = '📎 ' + f.name;
    analyzeBtn.disabled = false;
  }
});

function animateSteps() {
  let i = 1;
  const interval = setInterval(() => {
    if (i > 1) document.getElementById('s'+(i-1)).className = 'loading-step done';
    if (i <= 8) document.getElementById('s'+i).className = 'loading-step active';
    i++;
    if (i > 8) clearInterval(interval);
  }, 600);
}

async function analyzePDF() {
  const file = fileInput.files[0];
  if (!file) return;

  analyzeBtn.disabled = true;
  document.getElementById('loadingPanel').style.display = 'block';
  document.getElementById('result').innerHTML = '';
  for (let i = 1; i <= 8; i++) document.getElementById('s'+i).className = 'loading-step';
  animateSteps();

  const formData = new FormData();
  formData.append('pdf', file);

  try {
    const res = await fetch('/analyze', { method: 'POST', body: formData });
    const data = await res.json();
    document.getElementById('loadingPanel').style.display = 'none';

    if (data.error) {
      document.getElementById('result').innerHTML =
        `<div class="error-panel">⚠ ERROR: ${data.error}</div>`;
    } else {
      renderResult(data);
    }
  } catch (e) {
    document.getElementById('loadingPanel').style.display = 'none';
    document.getElementById('result').innerHTML =
      `<div class="error-panel">⚠ Request failed: ${e.message}</div>`;
  }

  analyzeBtn.disabled = false;
}

function renderResult(d) {
  const risk = d.risk || {};
  const score = risk.score || 0;
  const severity = risk.severity || 'UNKNOWN';
  const fi = d.file_info || {};
  const iocs = d.iocs || {};
  const js = d.javascript || {};
  const breakdown = risk.breakdown || [];

  const scoreClass = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';
  const allIOCs = [
    ...(iocs.urls||[]).map(u => ({type:'URL', val:u})),
    ...(iocs.ips||[]).map(i => ({type:'IP', val:i})),
    ...(iocs.cves||[]).map(c => ({type:'CVE', val:c})),
    ...(iocs.embedded_files||[]).map(f => ({type:'FILE', val:f})),
    ...(iocs.emails||[]).map(e => ({type:'EMAIL', val:e})),
  ];

  const iocHTML = allIOCs.length
    ? allIOCs.map(i => `<li class="ioc-item"><span class="ioc-tag">${i.type}</span>${i.val}</li>`).join('')
    : `<div class="no-ioc">✓ No IOCs detected</div>`;

  const jsWarnings = [
    ...(js.obfuscation_patterns||[]).map(p => `Obfuscation: ${p}`),
    ...(js.auto_actions||[]).map(a => `Auto-action: ${a}`),
  ];

  document.getElementById('result').innerHTML = `
    <div class="result-panel">
      <div class="result-header">
        <div class="score-ring ${scoreClass}">${score}</div>
        <div class="result-meta">
          <h2>${fi.filename || 'Unknown file'}</h2>
          <p>${fi.size_human || ''} &nbsp;|&nbsp; MD5: ${(fi.md5||'').substring(0,16)}...</p>
        </div>
        <div class="verdict-badge verdict-${severity}">${severity}</div>
      </div>
      <div class="result-body">
        <div class="info-grid">
          <div class="info-card"><label>Risk Score</label><value>${score}/100</value></div>
          <div class="info-card"><label>Severity</label><value>${severity}</value></div>
          <div class="info-card"><label>Pages</label><value>${(d.objects||{}).page_count || 'N/A'}</value></div>
          <div class="info-card"><label>JS Blocks</label><value>${js.js_block_count || 0}</value></div>
          <div class="info-card"><label>Objects</label><value>${(d.objects||{}).total_objects || 'N/A'}</value></div>
          <div class="info-card"><label>Analysis Time</label><value>${d.analysis_time_seconds || '?'}s</value></div>
        </div>

        <div class="section-title">Indicators of Compromise</div>
        <ul class="ioc-list">${iocHTML}</ul>

        ${jsWarnings.length ? `
        <div class="section-title">JavaScript Threats</div>
        <ul class="ioc-list">${jsWarnings.map(w=>`<li class="ioc-item"><span class="ioc-tag">JS</span>${w}</li>`).join('')}</ul>
        ` : ''}

        ${breakdown.length ? `
        <div class="section-title">Score Breakdown</div>
        ${breakdown.map(b=>`<div class="breakdown-item">${b}</div>`).join('')}
        ` : ''}
      </div>
    </div>`;
}
</script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML)

@app.route('/analyze', methods=['POST'])
def analyze():

    if 'pdf' not in request.files:
        return jsonify({
            "error": "No file uploaded"
        })

    file = request.files['pdf']

    if 'pdf' not in request.files:
        return jsonify({
            "error": "No file uploaded"
        })

    file = request.files['pdf']

    text = ""
    suspicious_keywords = [
        "/JavaScript",
        "/JS",
        "/OpenAction",
        "/Launch",
        "cmd.exe",
        "powershell",
        "http://",
        "https://"
    ]

    found_keywords = []
    urls = []

    try:

        pdf_reader = PdfReader(file)

        for page in pdf_reader.pages:

            extracted = page.extract_text()

            if extracted:
                text += extracted

        text_lower = text.lower()

        score = 0

        for keyword in suspicious_keywords:

            if keyword.lower() in text_lower:

                found_keywords.append(keyword)

                score += 10

        words = text.split()

        for word in words:

            if word.startswith("http://") or word.startswith("https://"):

                urls.append(word)

                score += 5

        if score > 100:
            score = 100

        severity = "CLEAN"

        if score >= 70:
            severity = "HIGH"

        elif score >= 40:
            severity = "MEDIUM"

        elif score >= 10:
            severity = "LOW"

        return jsonify({

            "risk": {
                "score": score,
                "severity": severity,
                "breakdown": found_keywords
            },

            "file_info": {
                "filename": file.filename,
                "size_human": "Uploaded PDF",
                "md5": "generated-demo-md5"
            },

            "objects": {
                "page_count": len(pdf_reader.pages),
                "total_objects": len(found_keywords)
            },

            "javascript": {
                "js_block_count": text.count("/JS"),
                "obfuscation_patterns": [],
                "auto_actions": []
            },

            "iocs": {
                "urls": urls,
                "ips": [],
                "cves": [],
                "embedded_files": [],
                "emails": []
            },

            "analysis_time_seconds": 1
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        })

if __name__ == "__main__":
    app.run()