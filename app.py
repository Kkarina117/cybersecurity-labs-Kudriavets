from flask import Flask, render_template, request, g, redirect, url_for, flash
import sqlite3
import os
from datetime import datetime

DB_PATH = 'lab6.db'

app = Flask(__name__)
app.secret_key = 'secret-key-123'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        need_init = not os.path.exists(DB_PATH)
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        if need_init:
            init_db(db)
    return db

def init_db(db):
    cur = db.cursor()

    cur.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        fullname TEXT
    )
    ''')

    cur.execute('''
    CREATE TABLE students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        grade TEXT
    )
    ''')

    cur.execute('''
    CREATE TABLE attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT,
        payload TEXT,
        detected_at TEXT
    )
    ''')

    users = [
        ('admin', 'admin123', 'Адміністратор'),
        ('student', 'student123', 'Студент'),
    ]

    students = [
        ('Іван Іваненко', 'ivan@gmail.com', 'A'),
        ('Марія Петренко', 'maria@gmail.com', 'B'),
        ('Павло Шевченко', 'pavlo@gmail.com', 'C'),
    ]

    cur.executemany('INSERT INTO users VALUES (NULL,?,?,?)', users)
    cur.executemany('INSERT INTO students VALUES (NULL,?,?,?)', students)

    db.commit()

def log_attack(endpoint, payload):
    db = get_db()
    db.execute(
        'INSERT INTO attack_logs(endpoint,payload,detected_at) VALUES (?,?,?)',
        (endpoint, payload, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    db.commit()

@app.route('/')
def index():
    get_db()
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()

        if user:

            flash(f"✅ Успішний вхід! Ласкаво просимо, {user['fullname']}!", "success")
        else:
            flash("❌ Невірний логін або пароль!", "danger")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        fullname = request.form['fullname']

        db = get_db()

        # 1. Перевірка на існування логіну
        existing_user = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_user:
            flash("❌ Користувач з таким логіном вже існує! Спробуйте інший.", "danger")
            return render_template('register.html')

        # 2. Додавання нового користувача
        try:
            db.execute(
                "INSERT INTO users (username, password, fullname) VALUES (?, ?, ?)",
                (username, password, fullname)
            )
            db.commit()
            flash(f"✅ Успішна реєстрація! Ви можете увійти як {username}.", "success")
            # Перенаправлення на сторінку авторизації
            return redirect(url_for('login'))
        except Exception:
            flash("❌ Помилка при реєстрації. Спробуйте пізніше.", "danger")

    return render_template('register.html')

@app.route('/search-bad', methods=['GET', 'POST'])
def search_bad():
    results = []
    if request.method == 'POST':
        keyword = request.form['keyword']

        sql = f"SELECT * FROM students WHERE name LIKE '%{keyword}%'"

        db = get_db()
        try:
            results = db.execute(sql).fetchall()
            if "'" in keyword or "--" in keyword:
                log_attack("search-bad", keyword)
        except:
            flash("❌ Помилка SQL-запиту!", "danger")

    return render_template('search_bad.html', results=results)

@app.route('/search-good', methods=['GET', 'POST'])
def search_good():
    results = []
    if request.method == 'POST':
        keyword = request.form['keyword']

        sql = "SELECT * FROM students WHERE name LIKE ?"
        param = f"%{keyword}%"

        db = get_db()
        results = db.execute(sql, (param,)).fetchall()

    return render_template('search_good.html', results=results)

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()

if __name__ == '__main__':
    with app.app_context():
        get_db()
    app.run(debug=True)