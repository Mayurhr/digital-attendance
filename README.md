# 📚 Digital Attendance System (with Face Recognition)

A modern and secure **Digital Attendance System** built using **Flask**, **MySQL**, and **HTML/CSS/JS**. This system offers role-based access for **Admin**, **Teachers**, and **Students**, supports face image uploads, and enables smart attendance tracking and management.

---

## 🚀 Features

- 🔐 **Role-Based Login**: Separate dashboards for Admin, Teacher, and Student
- 📷 **Face Upload**: Image-based face data upload for attendance validation
- 🧑‍💼 **Admin Panel**:
  - Add users (Admin/Teacher/Student)
  - Manage users with photo support
  - Secure password hashing
- 📁 **Image Upload**: Securely upload and store face images in `static/faces/`
- 📊 **User Dashboards**: Basic role-specific landing pages (to be expanded)
- 🔐 **Secure Login System**: Passwords stored with bcrypt hashing
- 🌐 **Mobile + Web Compatible UI**

---

## 🛠️ Tech Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML5, CSS3, JS (Boxicons, custom UI)
- **Database**: MySQL
- **Libraries**:
  - `Flask-MySQLdb`
  - `bcrypt`
  - `Werkzeug` (for secure file uploads)
