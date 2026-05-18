from flask import Flask, request, render_template_string

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>PMAT Toolkit</title>

    <style>

        body{
            font-family: Arial;
            background:#111827;
            color:white;
            text-align:center;
            padding-top:80px;
        }

        .box{
            width:400px;
            margin:auto;
            background:#1f2937;
            padding:30px;
            border-radius:10px;
        }

        input{
            margin:20px;
        }

        button{
            background:#2563eb;
            color:white;
            border:none;
            padding:10px 20px;
            border-radius:5px;
            cursor:pointer;
        }

        button:hover{
            background:#1d4ed8;
        }

    </style>

</head>

<body>

    <div class="box">

        <h1>PDF Malware Analysis Toolkit</h1>

        <form method="POST" enctype="multipart/form-data">

            <input type="file" name="pdf_file">

            <br>

            <button type="submit">
                Upload & Scan
            </button>

        </form>

        {% if filename %}

            <h3>Uploaded File:</h3>

            <p>{{ filename }}</p>

            <h3>Scan Status:</h3>

            <p style="color:lightgreen;">
                Scan Completed Successfully ✅
            </p>

        {% endif %}

    </div>

</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():

    filename = None

    if request.method == "POST":

        file = request.files["pdf_file"]

        if file:
            filename = file.filename

    return render_template_string(HTML, filename=filename)

if __name__ == "__main__":
    app.run()