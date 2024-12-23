from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

def create_app():
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(16)

    # Database Connection
    def get_db_connection():
        if 'db' not in g:
            try:
                g.db = mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="Hemil@7647",
                    database="user_auth"
                )
            except Error as err:
                print(f"Database Connection Error: {err}")
                return None
        return g.db

    @app.route('/')
    def home():
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            db = get_db_connection()
            if not db:
                flash("Database connection failed.", "error")
                return redirect(url_for('login'))

            cursor = db.cursor()
            cursor.execute("SELECT id, password FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))

            flash("Invalid username or password.", "error")
        return render_template('login.html')

    @app.route('/dashboard')
    def dashboard():
        if 'user_id' not in session:
            flash("You must log in first.", "error")
            return redirect(url_for('login'))
        return f"Welcome to your dashboard, user {session['user_id']}"

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = generate_password_hash(request.form.get('password'))

            db = get_db_connection()
            if not db:
                flash("Database connection failed.", "error")
                return redirect(url_for('register'))

            cursor = db.cursor()

            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                flash("Username or Email already exists.", "error")
            else:
                cursor.execute(
                    "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, password)
                )
                db.commit()
                flash("Registration successful! Please log in.", "success")
                return redirect(url_for('login'))
        return render_template('register.html')

    @app.teardown_appcontext
    def close_db(error):
        db = g.pop('db', None)
        if db is not None:
            db.close()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
