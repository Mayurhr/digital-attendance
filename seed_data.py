"""
seed_data.py — generates a realistic, fully-linked DEMO dataset for a small PU College
(ABC PU College), used to test the complete workflow end-to-end before scaling the same
schema up to a full Engineering College with multiple branches and thousands of students.

PU College rewrite (replaces the previous Engineering College demo dataset): a single course
(Science) with two academic years — 1st PUC (Sections A, B) and 2nd PUC (Section A only) — 9
subjects per year, 13 teachers, 120 students, a conflict-free weekly timetable built from the
college's real period timings, ~2.5 weeks of attendance history, leave requests and
notifications.

No schema or application-logic changes were made for this rewrite. The existing generic
Branch(department) -> Year -> Section structure is reused as-is: "Branch" = Course ("Science"),
"Year" 1/2 = 1st PUC / 2nd PUC. Each PU year is treated as a single term (semester 1 for 1st
PUC, semester 3 for 2nd PUC) rather than splitting into two sub-semesters like the engineering
dataset did — semester_to_year() in app.py still resolves both back to the correct year.

Passwords are bcrypt-hashed in the database as always. The plaintext passwords used here are
documented in DEMO_CREDENTIALS.md — this script and that file must stay in sync.

Run with the database already created from schema.sql:
    python seed_data.py
"""

import os
import random
import io
import itertools
from datetime import date, timedelta, time as dtime

import pymysql
import bcrypt
from PIL import Image, ImageDraw

random.seed(42)  # reproducible dataset

DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USER', 'root')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'mayur@127')
DB_NAME = os.environ.get('DB_NAME', 'attendance_system')

ADMIN_PASSWORD = 'Admin@123'
TEACHER_PASSWORD = 'Teacher@123'
STUDENT_PASSWORD = 'Student@123'

UPLOAD_FOLDER = os.path.join('static', 'faces')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def hash_pw(pw):
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def make_avatar(initials, seed_color):
    """A simple placeholder avatar (colored circle + initials) — NOT a real face. Trying to
    register this for face recognition will correctly fail with 'no face detected', which is
    the honest behavior; real photos are needed for that."""
    img = Image.new('RGB', (200, 200), seed_color)
    draw = ImageDraw.Draw(img)
    draw.ellipse((10, 10, 190, 190), fill=tuple(min(255, c + 40) for c in seed_color))
    draw.text((70, 85), initials, fill=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format='JPEG')
    return buf.getvalue()


def save_avatar(name):
    initials = ''.join([p[0] for p in name.split() if p[0].isalpha()][:2]).upper()
    color = (random.randint(40, 180), random.randint(40, 180), random.randint(40, 180))
    filename = f"avatar_{name.replace(' ', '_').replace('.', '').lower()}_{random.randint(1000,9999)}.jpg"
    with open(os.path.join(UPLOAD_FOLDER, filename), 'wb') as f:
        f.write(make_avatar(initials, color))
    return filename


FIRST_NAMES = ['Aarav', 'Vivaan', 'Aditya', 'Vihaan', 'Arjun', 'Sai', 'Reyansh', 'Krishna',
               'Ishaan', 'Rohan', 'Ananya', 'Diya', 'Saanvi', 'Aadhya', 'Kiara', 'Myra',
               'Priya', 'Riya', 'Sneha', 'Pooja', 'Karthik', 'Suresh', 'Manoj', 'Deepak',
               'Lakshmi', 'Divya', 'Neha', 'Swati', 'Nikhil', 'Varun', 'Akash', 'Harish',
               'Meera', 'Shreya', 'Tanvi', 'Yashwant', 'Prakash', 'Ramesh', 'Anil', 'Kavya',
               'Gagan', 'Chetan', 'Bhavana', 'Nisha', 'Yogesh', 'Sandeep', 'Pallavi', 'Ravi']
LAST_NAMES = ['Sharma', 'Verma', 'Patil', 'Reddy', 'Iyer', 'Nair', 'Gupta', 'Rao',
              'Kulkarni', 'Joshi', 'Singh', 'Desai', 'Menon', 'Pillai', 'Shetty', 'Kumar',
              'Bhat', 'Hegde', 'Naik', 'Gowda', 'Kamath', 'Prabhu', 'Achar', 'Poojary']

# ---------- College / course structure ----------
# ABC PU College offers only Science for this small test dataset (Commerce omitted to keep
# things minimal — see project notes for scaling up later).
COLLEGE_NAME = 'ABC PU College'
DEPARTMENTS = [
    ('Science', 'SCI'),
]

# Year 1 = 1st PUC, Year 2 = 2nd PUC. 1st PUC is split into Sections A and B; 2nd PUC has only
# Section A — deliberately small so the whole workflow is easy to test end-to-end.
YEAR_SECTIONS = {
    'SCI': {1: ['A', 'B'], 2: ['A']},
}
YEAR_LABEL = {1: '1st PUC', 2: '2nd PUC'}

# Each PU year is treated as a single term. semester_to_year() in app.py maps semester 1 or 2
# back to year 1, and semester 3 or 4 back to year 2 — we just pick one semester number per
# year instead of splitting into two sub-terms like the engineering dataset did.
SEMESTER_BY_YEAR = {1: 1, 2: 3}

# ---------- Subjects: 9 PU Science subjects, one row per year (18 subject rows total) ----------
# code suffix 1 = 1st PUC, 2 = 2nd PUC (separate subject/exam per year, same as a real PU board).
SUBJECT_DEFS = {
    'SCI': [
        ('Physics', 'PHY1', 1), ('Physics', 'PHY2', 3),
        ('Chemistry', 'CHE1', 1), ('Chemistry', 'CHE2', 3),
        ('Mathematics', 'MAT1', 1), ('Mathematics', 'MAT2', 3),
        ('Biology', 'BIO1', 1), ('Biology', 'BIO2', 3),
        ('Computer Science', 'CSC1', 1), ('Computer Science', 'CSC2', 3),
        ('English', 'ENG1', 1), ('English', 'ENG2', 3),
        ('Kannada', 'KAN1', 1), ('Kannada', 'KAN2', 3),
        ('Hindi/Sanskrit', 'HIN1', 1), ('Hindi/Sanskrit', 'HIN2', 3),
        ('Physical Education', 'PED1', 1), ('Physical Education', 'PED2', 3),
    ],
}

# ---------- Teachers: name -> subject codes they teach ----------
# The four core science subjects have a dedicated teacher per PU year (typical for PU
# colleges); the remaining subjects are taught by the same teacher across both years.
TEACHER_DEFS = [
    ('Anitha Madam', ['PHY1']),
    ('Suresh Sir', ['PHY2']),
    ('Priya Madam', ['CHE1']),
    ('Ganesh Sir', ['CHE2']),
    ('Ramesh Sir', ['MAT1']),
    ('Lakshmi Madam', ['MAT2']),
    ('Deepa Madam', ['BIO1']),
    ('Mohan Sir', ['BIO2']),
    ('Kavya Madam', ['CSC1', 'CSC2']),
    ('Nandini Madam', ['ENG1', 'ENG2']),
    ('Shivakumar Sir', ['KAN1', 'KAN2']),
    ('Vinod Sir', ['HIN1', 'HIN2']),
    ('Manjunath Sir', ['PED1', 'PED2']),
]

# Subjects taught in a dedicated lab/venue rather than the class's own room.
LAB_SUBJECTS = {'Physics': 'Physics Lab', 'Chemistry': 'Chemistry Lab',
                'Biology': 'Biology Lab', 'Computer Science': 'Computer Lab'}

WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri']
# ABC PU College's real daily period timings (9:00 AM - 4:30 PM), break 11:30-11:50 and lunch
# 12:40-1:30 excluded, Activity/Tutorial (4:00-4:30) excluded since it isn't a subject period.
SLOT_TIMES = [
    (dtime(9, 0), dtime(9, 50)),    # 1st Period
    (dtime(9, 50), dtime(10, 40)),  # 2nd Period
    (dtime(10, 40), dtime(11, 30)), # 3rd Period
    (dtime(11, 50), dtime(12, 40)), # 4th Period
    (dtime(13, 30), dtime(14, 20)), # 5th Period
    (dtime(14, 20), dtime(15, 10)), # 6th Period
    (dtime(15, 10), dtime(16, 0)),  # 7th Period
]


def semester_to_year(semester):
    return ((semester - 1) // 2) + 1


def main():
    conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, autocommit=False)
    cur = conn.cursor()

    print("Clearing existing data...")
    cur.execute("SET FOREIGN_KEY_CHECKS=0")
    for t in ['notifications', 'leave_requests', 'attendance', 'attendance_sessions', 'face_samples',
              'subject_enrollments', 'teacher_subjects', 'teacher_subject_requests', 'timetable',
              'class_sections', 'subjects', 'students', 'teachers', 'users', 'departments', 'campus_settings']:
        cur.execute(f"TRUNCATE TABLE {t}")
    cur.execute("SET FOREIGN_KEY_CHECKS=1")
    conn.commit()

    used_names = set()

    def unique_name():
        while True:
            name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
            if name not in used_names:
                used_names.add(name)
                return name

    # ---------- Course (Department) ----------
    dept_ids = {}
    for name, code in DEPARTMENTS:
        cur.execute("INSERT INTO departments (name, code) VALUES (%s,%s)", (name, code))
        dept_ids[code] = cur.lastrowid
    conn.commit()
    print(f"Created {len(dept_ids)} course(s) for {COLLEGE_NAME}")

    # ---------- Class structure: Course -> Year (PUC) -> Section ----------
    section_count = 0
    for code, years in YEAR_SECTIONS.items():
        for year, sections in years.items():
            for section in sections:
                cur.execute(
                    "INSERT INTO class_sections (department_id, year, section) VALUES (%s,%s,%s)",
                    (dept_ids[code], year, section),
                )
                section_count += 1
    conn.commit()
    print(f"Created {section_count} class sections ({', '.join(f'{YEAR_LABEL[y]}-{s}' for c in YEAR_SECTIONS.values() for y, secs in c.items() for s in secs)})")

    # ---------- Admin ----------
    photo = save_avatar("System Administrator")
    cur.execute("INSERT INTO users (username,name,password,role,photo_filename) VALUES (%s,%s,%s,'admin',%s)",
                ('admin', 'System Administrator', hash_pw(ADMIN_PASSWORD), photo))
    conn.commit()
    print("Created admin account")

    # ---------- Subjects (9 per PU year x 2 years = 18 rows) ----------
    subjects = {}  # code -> dict
    for dept, defs in SUBJECT_DEFS.items():
        for name, code, sem in defs:
            cur.execute("INSERT INTO subjects (name,code,department_id,semester) VALUES (%s,%s,%s,%s)",
                        (name, code, dept_ids[dept], sem))
            subjects[code] = {'id': cur.lastrowid, 'dept': dept, 'sem': sem, 'name': name, 'code': code}
    conn.commit()
    print(f"Created {len(subjects)} subjects across 1st PUC and 2nd PUC")

    # ---------- Teachers ----------
    teachers = []
    teacher_by_subject_code = {}
    for i, (name, codes) in enumerate(TEACHER_DEFS, start=1):
        username = f"teacher{i}"
        photo = save_avatar(name)
        cur.execute("INSERT INTO users (username,name,password,role,photo_filename) VALUES (%s,%s,%s,'teacher',%s)",
                    (username, name, hash_pw(TEACHER_PASSWORD), photo))
        user_id = cur.lastrowid
        emp_code = f"EMP{2000 + i}"
        phone = f"98{random.randint(10000000, 99999999)}"
        cur.execute("INSERT INTO teachers (user_id, department_id, employee_code, phone) VALUES (%s,%s,%s,%s)",
                    (user_id, dept_ids['SCI'], emp_code, phone))
        teacher = {'id': cur.lastrowid, 'user_id': user_id, 'dept': 'SCI', 'name': name,
                   'username': username, 'emp_code': emp_code, 'subjects': codes}
        teachers.append(teacher)
        for code in codes:
            teacher_by_subject_code[code] = teacher
    conn.commit()
    print(f"Created {len(teachers)} teachers")

    # ---------- Teacher-subject assignments, one row per configured section ----------
    teacher_subjects = []
    for sub in subjects.values():
        teacher = teacher_by_subject_code[sub['code']]
        year = semester_to_year(sub['sem'])
        sections = YEAR_SECTIONS[sub['dept']].get(year, ['A'])
        for section in sections:
            cur.execute(
                "INSERT INTO teacher_subjects (teacher_id, subject_id, section, semester) VALUES (%s,%s,%s,%s)",
                (teacher['id'], sub['id'], section, sub['sem']),
            )
            teacher_subjects.append({'id': cur.lastrowid, 'teacher': teacher, 'subject': sub, 'section': section})
    conn.commit()
    print(f"Created {len(teacher_subjects)} teacher-subject assignments")

    # ---------- Timetable (conflict-free by construction: a single shuffled pool of the
    # college's 35 weekly period slots (7 periods x 5 days) is handed out one-at-a-time to each
    # teacher-subject-section entry, so no teacher ever lands on two slots at once) ----------
    all_slots = [(d, s, e) for d in WEEKDAYS for s, e in SLOT_TIMES]  # 35 combinations
    slot_cycle = itertools.cycle(random.sample(all_slots, len(all_slots)))
    timetable_count = 0
    for ts in teacher_subjects:
        day, start, end = next(slot_cycle)
        year = semester_to_year(ts['subject']['sem'])
        room = LAB_SUBJECTS.get(ts['subject']['name'], f"{YEAR_LABEL[year]} {ts['section']} Classroom")
        cur.execute(
            """INSERT INTO timetable (subject_id, section, semester, day_of_week, start_time, end_time, room)
               VALUES (%s,%s,%s,%s,%s,%s,%s)""",
            (ts['subject']['id'], ts['section'], ts['subject']['sem'], day, start, end, room),
        )
        timetable_count += 1
    conn.commit()
    print(f"Created {timetable_count} conflict-free timetable entries")

    # ---------- Students (1st PUC A: 40, 1st PUC B: 40, 2nd PUC A: 40 = 120 total) ----------
    students = []
    for dept, years in YEAR_SECTIONS.items():
        for year, sections in years.items():
            sem = SEMESTER_BY_YEAR[year]
            for section in sections:
                for i in range(1, 41):
                    name = unique_name()
                    roll = f"{year}PU{section}{i:03d}"
                    photo = save_avatar(name)
                    cur.execute("INSERT INTO users (username,name,password,role,photo_filename) VALUES (%s,%s,%s,'student',%s)",
                                (roll, name, hash_pw(STUDENT_PASSWORD), photo))
                    user_id = cur.lastrowid
                    phone = f"97{random.randint(10000000, 99999999)}"
                    parent_phone = f"96{random.randint(10000000, 99999999)}"
                    id_card_number = f"ABC-{roll}"
                    cur.execute(
                        """INSERT INTO students (user_id, department_id, roll_number, semester, section, phone, parent_contact, student_code)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (user_id, dept_ids[dept], roll, sem, section, phone, parent_phone, id_card_number),
                    )
                    # Deliberate spread of attendance rates so risk-students/analytics pages have
                    # something realistic to show — not everyone at a uniform 90%.
                    base_rate = random.choice([0.95, 0.92, 0.88, 0.85, 0.8, 0.78, 0.7, 0.6, 0.5, 0.4])
                    students.append({'id': cur.lastrowid, 'user_id': user_id, 'dept': dept, 'year': year,
                                      'sem': sem, 'section': section, 'roll': roll, 'name': name,
                                      'base_rate': base_rate})
    conn.commit()
    print(f"Created {len(students)} students across 1st PUC (A, B) and 2nd PUC (A)")

    # ---------- Enrollments (each student takes the 9 subjects matching their PU year) ----------
    enrollment_count = 0
    for student in students:
        matching_subjects = [s for s in subjects.values() if s['dept'] == student['dept'] and s['sem'] == student['sem']]
        for sub in matching_subjects:
            cur.execute(
                "INSERT INTO subject_enrollments (student_id, subject_id, section, semester) VALUES (%s,%s,%s,%s)",
                (student['id'], sub['id'], student['section'], student['sem']),
            )
            enrollment_count += 1
    conn.commit()
    print(f"Created {enrollment_count} enrollments")

    # ---------- Attendance history (last ~2.5 weeks of weekdays) ----------
    today = date.today()
    session_dates = []
    d = today - timedelta(days=1)
    while len(session_dates) < 10 and d > today - timedelta(days=25):
        if d.weekday() < 5:
            session_dates.append(d)
        d -= timedelta(days=1)

    session_count, attendance_count = 0, 0
    for ts in teacher_subjects:
        enrolled = [s for s in students if s['dept'] == ts['subject']['dept']
                    and s['sem'] == ts['subject']['sem'] and s['section'] == ts['section']]
        if not enrolled:
            continue
        for sess_date in session_dates:
            start_t, end_t = random.choice(SLOT_TIMES)
            cur.execute(
                """INSERT INTO attendance_sessions
                       (teacher_id, subject_id, section, semester, session_date, start_time, end_time, mode, status)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,'manual','closed')""",
                (ts['teacher']['id'], ts['subject']['id'], ts['section'], ts['subject']['sem'],
                 sess_date, start_t, end_t),
            )
            session_id = cur.lastrowid
            session_count += 1
            for student in enrolled:
                status = 'present' if random.random() < student['base_rate'] else 'absent'
                cur.execute(
                    """INSERT INTO attendance
                           (session_id, student_id, teacher_id, subject_id, attendance_date, attendance_time, status, source)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,'manual')""",
                    (session_id, student['id'], ts['teacher']['id'], ts['subject']['id'],
                     sess_date, start_t, status),
                )
                attendance_count += 1
        if session_count % 200 == 0:
            conn.commit()
    conn.commit()
    print(f"Created {session_count} attendance sessions, {attendance_count} attendance records")

    # ---------- Leave requests ----------
    cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    admin_user_id = cur.fetchone()[0]
    leave_students = random.sample(students, min(15, len(students)))
    leave_count = 0
    for student in leave_students:
        matching_subjects = [s for s in subjects.values() if s['dept'] == student['dept'] and s['sem'] == student['sem']]
        subject = random.choice(matching_subjects) if matching_subjects and random.random() > 0.3 else None
        from_offset = random.randint(2, 20)
        from_date = today - timedelta(days=from_offset)
        to_date = from_date + timedelta(days=random.randint(0, 2))
        status = random.choice(['approved', 'approved', 'rejected', 'pending'])
        reason = random.choice(['Medical leave — fever', 'Family function', 'Personal emergency',
                                 'Not feeling well', 'Family function out of town'])
        cur.execute(
            """INSERT INTO leave_requests (student_id, subject_id, from_date, to_date, reason, status, decided_by, decided_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (student['id'], subject['id'] if subject else None, from_date, to_date, reason, status,
             admin_user_id if status != 'pending' else None, today if status != 'pending' else None),
        )
        leave_count += 1
    conn.commit()
    print(f"Created {leave_count} leave requests")

    # ---------- Notifications (a realistic sample, not one per attendance event) ----------
    notif_count = 0
    at_risk = [s for s in students if s['base_rate'] < 0.75]
    for student in at_risk[:12]:
        cur.execute(
            "INSERT INTO notifications (user_id, title, message, type) VALUES (%s,%s,%s,'attendance')",
            (student['user_id'], "Low attendance warning",
             "Your attendance is below the 75% requirement. Please attend upcoming classes regularly."),
        )
        notif_count += 1
    for teacher in teachers[:6]:
        cur.execute(
            "INSERT INTO notifications (user_id, title, message, type) VALUES (%s,%s,%s,'request')",
            (teacher['user_id'], "Subject assignment approved",
             "You are now assigned to teach your requested subject."),
        )
        notif_count += 1
    cur.execute(
        "INSERT INTO notifications (user_id, title, message, type) VALUES (%s,%s,%s,'system')",
        (admin_user_id, "Demo data loaded", f"{COLLEGE_NAME} demo dataset generated successfully."),
    )
    notif_count += 1
    conn.commit()
    print(f"Created {notif_count} notifications")

    # ---------- Campus settings (Bengaluru, matching a typical deployment) ----------
    cur.execute(
        "INSERT INTO campus_settings (id, latitude, longitude, radius_meters) VALUES (1, %s, %s, %s)",
        (12.9716, 77.5946, 300),
    )
    conn.commit()
    print("Set campus GPS location (demo values — update to your real campus in Admin > Campus GPS Settings)")

    cur.close()
    conn.close()
    print(f"\n{COLLEGE_NAME} demo dataset created successfully:")
    print(f"  1 course (Science) x 1st/2nd PUC, {section_count} class sections")
    print(f"  {len(teachers)} teachers, {len(subjects)} subjects, {len(students)} students")
    print(f"  {timetable_count} timetable entries, {enrollment_count} enrollments")
    print("See DEMO_CREDENTIALS.md for login details.")


if __name__ == '__main__':
    main()
