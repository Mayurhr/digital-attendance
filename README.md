# 📚 Digital Attendance System (with Face Recognition)

A modern, secure, and responsive **Digital Attendance System** built using **Flask**, **MySQL**, and **HTML/CSS/JS**. This system enables role-based access for **Admin**, **Teachers**, and **Students**, supports face image uploads, and offers intuitive attendance management.  

---

## 🚀 Features

- 🔐 **Role-Based Login**  
  - Separate dashboards for Admin, Teacher, and Student  
- 📷 **Face Upload**  
  - Upload image-based face data for attendance validation  
- 🧑‍💼 **Admin Panel**  
  - Add users (Admin/Teacher/Student)  
  - Manage users with photo support  
  - Edit roles & delete users securely  
  - Password reset & secure hashing  
- 📁 **Image Upload**  
  - Store face images securely in `static/faces/`  
- 📊 **User Dashboards**  
  - Basic role-specific landing pages (placeholders for now)  
- 🔐 **Secure Login System**  
  - Passwords stored with bcrypt hashing  
- 🌐 **Mobile + Web Compatible UI**  

---

## 🛠️ Tech Stack

- **Backend**: Flask (Python)  
- **Frontend**: HTML5, CSS3, JavaScript (Boxicons, custom UI)  
- **Database**: MySQL  
- **Libraries**:  
  - `Flask-MySQLdb` — MySQL integration  
  - `bcrypt` — Secure password hashing  
  - `Werkzeug` — Secure file uploads  

---

## 📂 Project Structure
```
digital-attendance-system/
│
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── static/
│   ├── faces/               # Uploaded face images are saved here        
├── templates/
│   ├── login.html           # Login page
│   ├── admin_dashboard.html # Admin dashboard
│   ├── add.html             # Add user form
│   ├── manage_users.html    # Manage users table
│   └── settings.html        # Change password form
└── README.md                # Project documentation
```

---

## 📦 Installation & Requirements

### 1️⃣ Prerequisites
- Python **3.8+**  
- pip (Python package manager)  
- MySQL Server  
- Git (optional, for cloning the repo)  

---

### 2️⃣ Clone the Repository
```bash
git clone https://github.com/your-username/digital-attendance-system.git
cd digital-attendance-system
```

---

### 3️⃣ Install Required Python Packages

#### Install from `requirements.txt`:
```bash
pip install -r requirements.txt
```

#### Or install manually:
```bash
pip install Flask==3.0.3
pip install flask-mysqldb==2.0.0
pip install bcrypt==4.2.0
pip install mysqlclient==2.2.4
```

---

## 🔑 Environment Variables Setup
Instead of hardcoding your credentials in `app.py`, create a **.env** file in your project root:  
```
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password
MYSQL_DB=attendance_system
SECRET_KEY=your_secret_key
```

Install **python-dotenv**:
```bash
pip install python-dotenv
```

Update `app.py`:
```python
from dotenv import load_dotenv
load_dotenv()

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.secret_key = os.getenv('SECRET_KEY')
```

---

## 🗄️ Database Setup
1. Log in to MySQL:
```bash
mysql -u root -p
```
2. Create the database:
```sql
CREATE DATABASE attendance_system;
```
3. Create the `users` table:
```sql
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100),
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'teacher', 'student') NOT NULL,
    photo_filename VARCHAR(255)
);
```

---

## ▶️ Running the Application
```bash
python app.py
```
Visit:  
```
http://127.0.0.1:5000
```

---

## 👥 Role-Based Usage

### 🔹 Admin
- Add users (Admin, Teacher, Student)  
- Manage, edit, and delete users  
- Change password  
- Upload student photos  

### 🔹 Teacher *(placeholder)*
- View assigned class attendance  
- Mark attendance *(future feature)*  

### 🔹 Student *(placeholder)*
- View personal attendance records  

---

🚀 **Built with passion and precision — ready to make attendance smarter and faster!**
