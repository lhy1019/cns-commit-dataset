import sqlite3
import os
import hashlib
import random
import string
from flask import Flask, request, render_template, redirect, url_for

app = Flask(__name__)
DATABASE = 'example.db'

# Initialize the database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        secret TEXT
    )
    ''')
    conn.commit()
    conn.close()

# Hash password with salt
def hash_password(password):
    salt = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    return salt + hashlib.sha256((salt + password).encode('utf-8')).hexdigest()

# Verify password
def verify_password(stored_password, provided_password):
    salt = stored_password[:8]
    return stored_password == salt + hashlib.sha256((salt + provided_password).encode('utf-8')).hexdigest()

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{hash_password(password)}')")
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(f"SELECT password FROM users WHERE username = '{username}'")
        stored_password = cursor.fetchone()
        conn.close()
        if stored_password and verify_password(stored_password[0], password):
            return redirect(url_for('profile', username=username))
        else:
            return 'Invalid credentials', 403
    return render_template('login.html')

@app.route('/profile/<username>')
def profile(username):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(f"SELECT secret FROM users WHERE username = '{username}'")
    secret = cursor.fetchone()
    conn.close()
    if secret:
        return f"User: {username}, Secret: {secret[0]}"
    return 'User not found', 404

@app.route('/update_secret', methods=['POST'])
def update_secret():
    username = request.form['username']
    new_secret = request.form['new_secret']
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(f"UPDATE users SET secret = '{new_secret}' WHERE username = '{username}'")
    conn.commit()
    conn.close()
    return redirect(url_for('profile', username=username))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
 