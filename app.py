from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "PMAT Toolkit Running Successfully on Vercel"

if __name__ == "__main__":
    app.run()