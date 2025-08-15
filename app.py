from flask import Flask, render_template, request, redirect, session, flash, jsonify
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
            flash("User added successfully.")
        except Exception as e:
            flash("Failed to add user. Username may already exist.")
        finally:
            cur.close()

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

@app.route('/admin/scanner')
def scanner():
    if session.get('role') != 'admin':
        return redirect('/login')
    return "Scanner Placeholder"


@app.route('/admin/manage-users')
def manage_users():
    if session.get('role') != 'admin':
        return redirect('/login')
    return render_template('manage_users.html')


@app.route('/api/users')
def get_users_api():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username, name, role, photo_filename FROM users")
    users = cur.fetchall()
    cur.close()

    user_list = []
    for user in users:
        user_list.append({
            'id': user[0],
            'username': user[1],
            'name': user[2],
            'role': user[3],
            'photo_url': f"/static/faces/{user[4]}" if user[4] else None
        })

    return jsonify({'success': True, 'users': user_list})


@app.route('/api/users/save', methods=['POST'])
def save_user_changes():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    password = data.get('password')
    changes = data.get('changes', [])

    if not changes:
        return jsonify({'success': False, 'message': 'No changes provided'})

    cur = mysql.connection.cursor()
    cur.execute("SELECT password FROM users WHERE id = %s", (session['user_id'],))
    admin_pw = cur.fetchone()[0]

    if not bcrypt.checkpw(password.encode('utf-8'), admin_pw.encode('utf-8')):
        return jsonify({'success': False, 'message': 'Invalid admin password'})

    try:
        for change in changes:
            user_id = change['id']
            field = change['field']
            new_value = change['newValue']

            if field == 'role' and new_value not in ['admin', 'teacher', 'student']:
                continue
            if field == 'status' and new_value not in ['active', 'inactive', 'suspended']:
                continue

            cur.execute(f"UPDATE users SET {field} = %s WHERE id = %s", (new_value, user_id))

        mysql.connection.commit()
        return jsonify({'success': True, 'message': 'Changes saved successfully'})
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'success': False, 'message': f'Error saving changes: {str(e)}'})
    finally:
        cur.close()


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    password = data.get('password')
    if not password:
        return jsonify({'success': False, 'message': 'Admin password is required'})

    cur = mysql.connection.cursor()
    cur.execute("SELECT password FROM users WHERE id = %s", (session['user_id'],))
    admin_pw = cur.fetchone()[0]

    if not bcrypt.checkpw(password.encode('utf-8'), admin_pw.encode('utf-8')):
        return jsonify({'success': False, 'message': 'Invalid admin password'})

    if user_id == session['user_id']:
        return jsonify({'success': False, 'message': 'Cannot delete your own account'})

    try:
        cur.execute("SELECT photo_filename FROM users WHERE id = %s", (user_id,))
        result = cur.fetchone()
        photo_filename = result[0] if result else None

        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        mysql.connection.commit()

        if photo_filename:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
            except OSError:
                pass

        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'success': False, 'message': f'Error deleting user: {str(e)}'})
    finally:
        cur.close()


@app.route('/api/users/<int:user_id>/reset-password', methods=['POST'])
def reset_password(user_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    password = data.get('password')
    if not password:
        return jsonify({'success': False, 'message': 'Admin password is required'})

    cur = mysql.connection.cursor()
    cur.execute("SELECT password FROM users WHERE id = %s", (session['user_id'],))
    admin_pw = cur.fetchone()[0]

    if not bcrypt.checkpw(password.encode('utf-8'), admin_pw.encode('utf-8')):
        return jsonify({'success': False, 'message': 'Invalid admin password'})

    import secrets, string
    alphabet = string.ascii_letters + string.digits
    new_password = ''.join(secrets.choice(alphabet) for _ in range(8))
    hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_pw, user_id))
        mysql.connection.commit()
        return jsonify({'success': True, 'message': f'Password reset successfully. New password: {new_password}'})
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'success': False, 'message': f'Error resetting password: {str(e)}'})
    finally:
        cur.close()


@app.route('/api/users', methods=['POST'])
def create_user():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    username = data.get('username')
    name = data.get('name')
    role = data.get('role')
    password = data.get('password')

    if not all([username, name, role, password]):
        return jsonify({'success': False, 'message': 'All fields are required'})
    if role not in ['admin', 'teacher', 'student']:
        return jsonify({'success': False, 'message': 'Invalid role'})

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO users (username, name, role, password)
            VALUES (%s, %s, %s, %s)
        """, (username, name, role, hashed_pw))
        mysql.connection.commit()
        return jsonify({'success': True, 'message': 'User created successfully'})
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'success': False, 'message': f'Error creating user: {str(e)}'})
    finally:
        cur.close()

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json() or {}
    username = data.get('username')
    name = data.get('name')
    role = data.get('role')

    # Basic validation
    if role and role not in ['admin', 'teacher', 'student']:
        return jsonify({'success': False, 'message': 'Invalid role'})

    try:
        cur = mysql.connection.cursor()
        # Build dynamic update
        fields, values = [], []
        if username is not None: fields.append("username=%s"); values.append(username)
        if name is not None: fields.append("name=%s"); values.append(name)
        if role is not None: fields.append("role=%s"); values.append(role)

        if not fields:
            return jsonify({'success': False, 'message': 'No fields to update'})

        values.append(user_id)
        cur.execute(f"UPDATE users SET {', '.join(fields)} WHERE id=%s", tuple(values))
        mysql.connection.commit()
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'success': False, 'message': str(e)})
    finally:
        cur.close()

if __name__ == '__main__':
    app.run(debug=True)
