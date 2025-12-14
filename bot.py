import os
from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__, template_folder='templates')

# Basit rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)

@app.route("/")
@limiter.limit("50 per minute")
def index():
    return render_template("index.html")

@app.route("/health")
def health():
    return jsonify({"status": "healthy"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
