from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
from datetime import datetime
from waf import detect_attack, classify_attack
import os

app = Flask(__name__)
app.secret_key = "smartwaf_secret_key_please_change"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "waf_logs.db")

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS blocked_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_text TEXT,
            attack_type TEXT,
            ip TEXT,
            created_at TEXT
        )
    """)
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

@app.before_first_request
def setup():
    init_db()

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/submit", methods=["POST"])
def submit():
    user_input = request.form.get("user_input", "")
    ip = request.remote_addr or "unknown"
    is_attack = detect_attack(user_input)
    if is_attack:
        atype = classify_attack(user_input)
        # log to db
        db = get_db()
        db.execute(
            "INSERT INTO blocked_requests (input_text, attack_type, ip, created_at) VALUES (?,?,?,?)",
            (user_input, atype, ip, datetime.utcnow().isoformat())
        )
        db.commit()
        return render_template("blocked.html", input_text=user_input, attack_type=atype)
    else:
        return render_template("allowed.html", input_text=user_input)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form.get("username","")
    password = request.form.get("password","")
    if username == "admin" and password == "admin123":
        session["admin_logged_in"] = True
        return redirect(url_for("smartadmin"))
    else:
        return render_template("login.html", error="Invalid credentials")

@app.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("index"))

@app.route("/smartadmin")
def smartadmin():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
    db = get_db()
    cur = db.execute("SELECT * FROM blocked_requests ORDER BY created_at DESC LIMIT 100")
    rows = cur.fetchall()
    return render_template("dashboard.html", rows=rows)

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    # app.run(debug=True)