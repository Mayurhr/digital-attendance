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

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect('/login')
    return render_template('admin_dashboard.html', username=session['username'])

@app.route('/admin/add-user', methods=['GET', 'POST'])
def add_user():
    if session.get('role') != 'admin':
        return redirect('/login')

    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        photo = request.files.get('photo')

        # Debug Print
        print(f"DEBUG: name={name}, username={username}, role={role}, photo={photo.filename if photo else None}")

        if role not in ['admin', 'teacher', 'student']:
            flash("Invalid Role Selected. Please choose a valid role.")
            return redirect('/admin/add-user')

        photo_filename = None
        if role == 'student' and photo and photo.filename != '':
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO users (username, name, password, role, photo_filename)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, name, hashed_pw, role, photo_filename))
            mysql.connection.commit()
            print("User inserted successfully.")
        except Exception as e:
            print("Insert failed:", e)
            flash("Failed to add user. Check server logs.")
            return redirect('/admin/add-user')
        finally:
            cur.close()

        flash("User added successfully.")
        return redirect('/admin/add-user')

    return render_template('add.html')

@app.route('/admin/view-attendance')
def view_attendance():
    if session.get('role') != 'admin':
        return redirect('/login')
    return "View Attendance Placeholder"

@app.route('/admin/settings', methods=['GET', 'POST'])
def settings():
    if session.get('role') != 'admin':
        return redirect('/login')

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        user_id = session.get('user_id')
        cur = mysql.connection.cursor()
        cur.execute("SELECT password FROM users WHERE id = %s", (user_id,))
        result = cur.fetchone()

        if result and bcrypt.checkpw(old_password.encode('utf-8'), result[0].encode('utf-8')):
            if new_password == confirm_password:
                new_hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cur.execute("UPDATE users SET password = %s WHERE id = %s", (new_hashed_pw, user_id))
                mysql.connection.commit()
                flash("Password updated successfully!")
            else:
                flash("New passwords do not match.")
        else:
            flash("Old password is incorrect.")
        cur.close()
        return redirect('/admin/settings')

    return render_template('settings.html')

@app.route('/admin/manage-users')
def manage_users():
    if session.get('role') != 'admin':
        return redirect('/login')
    return "Manage Users Placeholder"

@app.route('/admin/scanner')
def scanner():
    if session.get('role') != 'admin':
        return redirect('/login')
    return "Scanner Placeholder"

if __name__ == '__main__':
    app.run(debug=True)
