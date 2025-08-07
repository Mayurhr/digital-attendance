from flask import Flask, render_template, request, redirect, session, flash
from flask_mysqldb import MySQL
import bcrypt
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mayur@127'
app.config['MYSQL_DB'] = 'attendance_system'

mysql = MySQL(app)

UPLOAD_FOLDER = os.path.join('static', 'faces')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role_input = request.form['role']

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, username, password, role FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user:
            db_id = user[0]
            db_username = user[1]
            db_password_hash = user[2]
            db_role = user[3]

            if bcrypt.checkpw(password.encode('utf-8'), db_password_hash.encode('utf-8')):
                if role_input == db_role:
                    session['username'] = db_username
                    session['role'] = db_role
                    session['user_id'] = db_id

                    if db_role == 'admin':
                        return redirect('/admin/dashboard')
                    elif db_role == 'teacher':
                        return "Teacher Dashboard Placeholder"
                    elif db_role == 'student':
                        return "Student Dashboard Placeholder"
                else:
                    flash("Role mismatch.")
            else:
                flash("Incorrect password.")
        else:
            flash("User not found.")

        return redirect('/login')

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
