from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>PMAT Toolkit</title>
</head>
<body style="font-family: Arial; text-align:center; padding-top:50px;">

    <h1>PDF Malware Analysis Toolkit</h1>

    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="pdf_file">
        <br><br>
        <button type="submit">Upload & Scan</button>
    </form>

    {% if filename %}
        <h3>Uploaded File:</h3>
        <p>{{ filename }}</p>

        <h3>Scan Result:</h3>
        <p>No malware detected (Demo Mode)</p>
    {% endif %}

</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():

    filename = None

    if request.method == "POST":

        file = request.files["pdf_file"]

        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)

            filename = file.filename

    return render_template_string(HTML, filename=filename)

if __name__ == "__main__":
    app.run()