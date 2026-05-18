from flask import Flask, render_template_string

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>PMAT Toolkit</title>
</head>
<body style="font-family: Arial; text-align:center; padding-top:50px;">

    <h1>PDF Malware Analysis Toolkit</h1>

    <h3>Deployment Successful ✅</h3>

</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML)