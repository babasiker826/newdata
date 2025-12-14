import os
import re
from flask import Flask, render_template, request, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)

# 🔐 Güvenlik Header'ları
Talisman(app)

# 🚦 Rate Limit / DDoS önlem
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)

# 🧼 SQLi & XSS filtre
def is_safe_input(text):
    blacklist = [
        r"(--|\b(SELECT|UPDATE|DELETE|INSERT|DROP|ALTER)\b)",
        r"(<script>|</script>)"
    ]
    for pattern in blacklist:
        if re.search(pattern, text, re.IGNORECASE):
            return False
    return True

@app.route("/")
@limiter.limit("10 per second")
def index():
    return render_template("index.html")

@app.route("/submit", methods=["POST"])
@limiter.limit("5 per minute")
def submit():
    data = request.form.get("data", "")
    if not is_safe_input(data):
        abort(403)
    return "OK"

@app.errorhandler(403)
def forbidden(e):
    return "Erişim engellendi", 403

@app.errorhandler(404)
def not_found(e):
    return "Bulunamadı", 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
