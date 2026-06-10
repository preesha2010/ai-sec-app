from dotenv import load_dotenv
load_dotenv()
from flask import Flask, redirect, render_template, request, jsonify, url_for
import sqlite3
import os
import hashlib

app = Flask(__name__)   # creating the Flask application instance

DATABASE = "users.db"   # database file name

SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# SECRET_KEY = "hardcoded"    # hardcoded pswd
# ADMIN_PASSWORD = "admin_123"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():    # register user with form
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')     # plaintext pswd
        conn = get_db()
        hashed = hashlib.sha256(password.encode()).hexdigest()
        conn.execute('INSERT INTO users(username, password) VALUES(?,?)', (username, hashed))
        # conn.execute('INSERT INTO users(username, password) VALUES(?,?)', (username, password))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template("register.html", success=False)
    
@app.route('/login', methods=['GET', 'POST'])
def login():    # user login with form`
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed = hashlib.sha256(password.encode()).hexdigest()
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?',(username, hashed)).fetchone()
        # user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?',(username, password)).fetchone()
        conn.close()
        if user:
            return redirect(url_for('home'))
        return render_template("login.html",success=False,error=True)
    return render_template("login.html", success=False, error=False)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        password = request.form.get("password")
        if password == ADMIN_PASSWORD:
            conn = get_db()
            users = conn.execute('SELECT * FROM users').fetchall()
            conn.close()
            return render_template("admin.html",granted=True,error=False,users=users)
        return render_template("admin.html",granted=False,error=True)
    return render_template("admin.html",granted=False,error=False)
    
# testing 123

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)