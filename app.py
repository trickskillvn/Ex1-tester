from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import re
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'super_secret_key'
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
JWT_SECRET = 'jwt_secret_key'  # Thay bằng key bảo mật trong production

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS candidates (
            user_id INTEGER PRIMARY KEY,
            full_name TEXT NOT NULL,
            dob TEXT,
            gender TEXT,
            skills TEXT,
            languages TEXT,
            experience TEXT,
            education TEXT,
            introduction TEXT,
            avatar TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS companies (
            user_id INTEGER PRIMARY KEY,
            company_name TEXT NOT NULL,
            address TEXT,
            website TEXT,
            field TEXT,
            country TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            requirements TEXT NOT NULL,
            salary TEXT NOT NULL,
            address TEXT NOT NULL,
            education TEXT,
            experience TEXT,
            created_at TEXT,
            FOREIGN KEY(company_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS job_seeks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_id INTEGER,
            title TEXT NOT NULL,
            experience TEXT NOT NULL,
            education TEXT NOT NULL,
            description TEXT,
            created_at TEXT,
            FOREIGN KEY(candidate_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER,
            candidate_id INTEGER,
            cv_path TEXT,
            cover_letter TEXT,
            applied_at TEXT,
            FOREIGN KEY(job_id) REFERENCES jobs(id),
            FOREIGN KEY(candidate_id) REFERENCES users(id)
        )''')
        c.execute("SELECT * FROM users WHERE username = 'admin'")
        if not c.fetchone():
            c.execute("INSERT INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, ?)",
                      ('admin', generate_password_hash('Admin1234!'), 'admin@example.com', '0000000000', 'admin'))
                      
        conn.commit()

init_db()

def validate_password(password):
    if len(password) < 8 or len(password) > 16:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(role=None):
    def decorator(f):
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                flash('Vui lòng đăng nhập.', 'danger')
                return redirect(url_for('login'))
            if role and session['role'] != role:
                flash('Bạn không có quyền truy cập.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

def token_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'message': 'Token is missing'}), 401
            try:
                data = jwt.decode(token.replace('Bearer ', ''), JWT_SECRET, algorithms=["HS256"])
                current_user = data['user_id']
                user_role = data['role']
                if role and user_role != role:
                    return jsonify({'message': 'Unauthorized role'}), 403
            except:
                return jsonify({'message': 'Token is invalid'}), 401
            return f(current_user, user_role, *args, **kwargs)
        return decorated
    return decorator

# Web Routes
@app.route('/')
def home():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT j.*, c.company_name FROM jobs j JOIN companies c ON j.company_id = c.user_id ORDER BY j.created_at DESC")
    jobs = c.fetchall()
    conn.close()
    return render_template('home.html', jobs=jobs)

@app.route('/register/candidate', methods=['GET', 'POST'])
def register_candidate():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        full_name = request.form['full_name']
        dob = request.form['dob']
        gender = request.form['gender']
        skills = request.form.get('skills', '')
        languages = request.form.get('languages', '')
        experience = request.form.get('experience', '')
        education = request.form.get('education', '')
        introduction = request.form.get('introduction', '')
        avatar = request.files.get('avatar')

        if not validate_password(password):
            flash('Mật khẩu không hợp lệ (8-16 ký tự, chữ hoa, thường, số, ký tự đặc biệt).', 'danger')
            return redirect(url_for('register_candidate'))

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT * FROM users WHERE username = ? OR email = ? OR phone = ?", (username, email, phone))
            if c.fetchone():
                flash('Tài khoản, email hoặc số điện thoại đã tồn tại.', 'danger')
                return redirect(url_for('register_candidate'))
            
            avatar_path = ''
            if avatar and avatar.filename:
                filename = secure_filename(avatar.filename)
                avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                avatar_path = f'uploads/{filename}'

            c.execute("INSERT INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, ?)",
                      (username, generate_password_hash(password), email, phone, 'candidate'))
            user_id = c.lastrowid
            c.execute("INSERT INTO candidates (user_id, full_name, dob, gender, skills, languages, experience, education, introduction, avatar) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (user_id, full_name, dob, gender, skills, languages, experience, education, introduction, avatar_path))
            conn.commit()
            flash('Đăng ký thành công!', 'success')
            return redirect(url_for('login'))
        except:
            conn.rollback()
            flash('Đăng ký thất bại.', 'danger')
        finally:
            conn.close()
    return render_template('register_candidate.html')

@app.route('/register/company', methods=['GET', 'POST'])
def register_company():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        company_name = request.form['company_name']
        address = request.form.get('address', '')
        website = request.form.get('website', '')
        field = request.form.get('field', '')
        country = request.form.get('country', '')

        if not validate_password(password):
            flash('Mật khẩu không hợp lệ (8-16 ký tự, chữ hoa, thường, số, ký tự đặc biệt).', 'danger')
            return redirect(url_for('register_company'))

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT * FROM users WHERE username = ? OR email = ? OR phone = ?", (username, email, phone))
            if c.fetchone():
                flash('Tài khoản, email hoặc số điện thoại đã tồn tại.', 'danger')
                return redirect(url_for('register_company'))
            
            c.execute("INSERT INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, ?)",
                      (username, generate_password_hash(password), email, phone, 'company'))
            user_id = c.lastrowid
            c.execute("INSERT INTO companies (user_id, company_name, address, website, field, country) VALUES (?, ?, ?, ?, ?, ?)",
                      (user_id, company_name, address, website, field, country))
            conn.commit()
            flash('Đăng ký thành công!', 'success')
            return redirect(url_for('login'))
        except:
            conn.rollback()
            flash('Đăng ký thất bại.', 'danger')
        finally:
            conn.close()
    return render_template('register_company.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['username'] = user['username']
            flash('Đăng nhập thành công!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Tài khoản hoặc mật khẩu không hợp lệ.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Đăng xuất thành công!', 'success')
    return redirect(url_for('login'))

@app.route('/post-job', methods=['GET', 'POST'])
@login_required(role='company')
def post_job():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        requirements = request.form['requirements']
        salary = request.form['salary']
        address = request.form['address']
        education = request.form.get('education', '')
        experience = request.form.get('experience', '')
        created_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not all([title, description, requirements, salary, address]):
            flash('Vui lòng nhập đầy đủ thông tin bắt buộc.', 'danger')
            return redirect(url_for('post_job'))

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO jobs (company_id, title, description, requirements, salary, address, education, experience, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (session['user_id'], title, description, requirements, salary, address, education, experience, created_at))
            conn.commit()
            flash('Tạo công việc thành công!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            conn.rollback()
            flash(f'Tạo công việc thất bại: {str(e)}', 'danger')
        finally:
            conn.close()
    return render_template('post_job.html')

@app.route('/edit-job/<int:job_id>', methods=['GET', 'POST'])
@login_required(role='company')
def edit_job(job_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM jobs WHERE id = ? AND company_id = ?", (job_id, session['user_id']))
    job = c.fetchone()

    if not job:
        flash('Công việc không tồn tại hoặc bạn không có quyền.', 'danger')
        conn.close()
        return redirect(url_for('home'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        requirements = request.form['requirements']
        salary = request.form['salary']
        address = request.form['address']
        education = request.form.get('education', '')
        experience = request.form.get('experience', '')

        if not all([title, description, requirements, salary, address]):
            flash('Vui lòng nhập đầy đủ thông tin bắt buộc.', 'danger')
            conn.close()
            return redirect(url_for('edit_job', job_id=job_id))

        try:
            c.execute("UPDATE jobs SET title = ?, description = ?, requirements = ?, salary = ?, address = ?, education = ?, experience = ? WHERE id = ?",
                      (title, description, requirements, salary, address, education, experience, job_id))
            conn.commit()
            flash('Sửa thông tin thành công!', 'success')
            return redirect(url_for('my_jobs'))
        except:
            conn.rollback()
            flash('Sửa thông tin thất bại.', 'danger')
        finally:
            conn.close()
    conn.close()
    return render_template('post_job.html', job=job, edit=True)

@app.route('/delete-job/<int:job_id>')
@login_required(role='company')
def delete_job(job_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM jobs WHERE id = ? AND company_id = ?", (job_id, session['user_id']))
    job = c.fetchone()

    if not job:
        flash('Công việc không tồn tại hoặc bạn không có quyền.', 'danger')
        conn.close()
        return redirect(url_for('my_jobs'))

    try:
        c.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        conn.commit()
        flash('Tin đã được xóa thành công!', 'success')
    except:
        conn.rollback()
        flash('Không thể xóa tin.', 'danger')
    finally:
        conn.close()
    return redirect(url_for('my_jobs'))

@app.route('/my-jobs')
@login_required(role='company')
def my_jobs():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM jobs WHERE company_id = ? ORDER BY created_at DESC", (session['user_id'],))
    jobs = c.fetchall()
    conn.close()
    return render_template('my_jobs.html', jobs=jobs)

@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
@login_required(role='candidate')
def apply_job(job_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
    job = c.fetchone()
    
    if not job:
        flash('Công việc không tồn tại.', 'danger')
        conn.close()
        return redirect(url_for('home'))

    if request.method == 'POST':
        cv = request.files.get('cv')
        cover_letter = request.form.get('cover_letter', '')
        applied_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cv_path = ''

        if cv and cv.filename:
            filename = secure_filename(cv.filename)
            cv.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            cv_path = f'uploads/{filename}'

        try:
            c.execute("INSERT INTO applications (job_id, candidate_id, cv_path, cover_letter, applied_at) VALUES (?, ?, ?, ?, ?)",
                      (job_id, session['user_id'], cv_path, cover_letter, applied_at))
            conn.commit()
            flash('Ứng tuyển thành công!', 'success')
            return redirect(url_for('home'))
        except:
            conn.rollback()
            flash('Ứng tuyển thất bại.', 'danger')
        finally:
            conn.close()
    conn.close()
    return render_template('apply_job.html', job=job)

@app.route('/profile', methods=['GET', 'POST'])
@login_required(role='candidate')
def profile():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM candidates WHERE user_id = ?", (session['user_id'],))
    candidate = c.fetchone()

    if request.method == 'POST':
        full_name = request.form['full_name']
        dob = request.form['dob']
        gender = request.form['gender']
        skills = request.form.get('skills', '')
        languages = request.form.get('languages', '')
        experience = request.form.get('experience', '')
        education = request.form.get('education', '')
        introduction = request.form.get('introduction', '')
        avatar = request.files.get('avatar')

        avatar_path = candidate['avatar']
        if avatar and avatar.filename:
            filename = secure_filename(avatar.filename)
            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            avatar_path = f'uploads/{filename}'

        try:
            c.execute("UPDATE candidates SET full_name = ?, dob = ?, gender = ?, skills = ?, languages = ?, experience = ?, education = ?, introduction = ?, avatar = ? WHERE user_id = ?",
                      (full_name, dob, gender, skills, languages, experience, education, introduction, avatar_path, session['user_id']))
            conn.commit()
            flash('Sửa thông tin thành công!', 'success')
        except:
            conn.rollback()
            flash('Sửa thông tin thất bại.', 'danger')
        finally:
            conn.close()
        return redirect(url_for('profile'))
    conn.close()
    return render_template('profile.html', candidate=candidate)

@app.route('/post-job-seek', methods=['GET', 'POST'])
@login_required(role='candidate')
def post_job_seek():
    if request.method == 'POST':
        title = request.form['title']
        experience = request.form['experience']
        education = request.form['education']
        description = request.form.get('description', '')
        created_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not all([title, experience, education]):
            flash('Vui lòng nhập đầy đủ thông tin bắt buộc.', 'danger')
            return redirect(url_for('post_job_seek'))

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO job_seeks (candidate_id, title, experience, education, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                      (session['user_id'], title, experience, education, description, created_at))
            conn.commit()
            flash('Bài viết được tạo thành công!', 'success')
            return redirect(url_for('home'))
        except:
            conn.rollback()
            flash('Không thể tạo bài viết.', 'danger')
        finally:
            conn.close()
    return render_template('post_job_seek.html')

@app.route('/view-applicants/<int:job_id>')
@login_required(role='company')
def view_applicants(job_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT a.*, c.full_name, c.email FROM applications a JOIN candidates c ON a.candidate_id = c.user_id WHERE a.job_id = ?", (job_id,))
    applicants = c.fetchall()
    c.execute("SELECT title FROM jobs WHERE id = ?", (job_id,))
    job = c.fetchone()
    conn.close()
    return render_template('view_applicants.html', applicants=applicants, job=job)

@app.route('/admin')
@login_required(role='admin')
def admin():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT u.*, c.full_name, co.company_name FROM users u LEFT JOIN candidates c ON u.id = c.user_id LEFT JOIN companies co ON u.id = co.user_id WHERE u.role != 'admin'")
    users = c.fetchall()
    c.execute("SELECT j.*, c.company_name FROM jobs j JOIN companies c ON j.company_id = c.user_id")
    jobs = c.fetchall()
    c.execute("SELECT js.*, c.full_name FROM job_seeks js JOIN candidates c ON js.candidate_id = c.user_id")
    job_seeks = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users, jobs=jobs, job_seeks=job_seeks)

@app.route('/admin/delete-user/<int:user_id>')
@login_required(role='admin')
def delete_user(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        conn.commit()
        flash('Xóa tài khoản thành công!', 'success')
    except:
        conn.rollback()
        flash('Không thể xóa tài khoản.', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin'))

@app.route('/admin/delete-job/<int:job_id>')
@login_required(role='admin')
def delete_job_admin(job_id):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        conn.commit()
        flash('Xóa tin tuyển dụng thành công!', 'success')
    except:
        conn.rollback()
        flash('Không thể xóa tin tuyển dụng.', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin'))

@app.route('/admin/delete-job-seek/<int:job_seek_id>')
@login_required(role='admin')
def delete_job_seek_admin(job_seek_id):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM job_seeks WHERE id = ?", (job_seek_id,))
        conn.commit()
        flash('Xóa tin tìm việc thành công!', 'success')
    except:
        conn.rollback()
        flash('Không thể xóa tin tìm việc.', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin'))

# API Routes
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user['password'], password):
        token = jwt.encode({
            'user_id': user['id'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, JWT_SECRET, algorithm="HS256")
        return jsonify({'token': token, 'message': 'Login successful'}), 200
    return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/api/register/candidate', methods=['POST'])
def api_register_candidate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    phone = data.get('phone')
    full_name = data.get('full_name')
    dob = data.get('dob')
    gender = data.get('gender')
    skills = data.get('skills', '')
    languages = data.get('languages', '')
    experience = data.get('experience', '')
    education = data.get('education', '')
    introduction = data.get('introduction', '')

    if not validate_password(password):
        return jsonify({'message': 'Invalid password (8-16 chars, upper, lower, digit, special)'}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM users WHERE username = ? OR email = ? OR phone = ?", (username, email, phone))
        if c.fetchone():
            return jsonify({'message': 'Username, email, or phone already exists'}), 400
        
        c.execute("INSERT INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, ?)",
                  (username, generate_password_hash(password), email, phone, 'candidate'))
        user_id = c.lastrowid
        c.execute("INSERT INTO candidates (user_id, full_name, dob, gender, skills, languages, experience, education, introduction) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (user_id, full_name, dob, gender, skills, languages, experience, education, introduction))
        conn.commit()
        return jsonify({'message': 'Candidate registered successfully'}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'message': f'Registration failed: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/register/company', methods=['POST'])
def api_register_company():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    phone = data.get('phone')
    company_name = data.get('company_name')
    address = data.get('address', '')
    website = data.get('website', '')
    field = data.get('field', '')
    country = data.get('country', '')

    if not validate_password(password):
        return jsonify({'message': 'Invalid password (8-16 chars, upper, lower, digit, special)'}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM users WHERE username = ? OR email = ? OR phone = ?", (username, email, phone))
        if c.fetchone():
            return jsonify({'message': 'Username, email, or phone already exists'}), 400
        
        c.execute("INSERT INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, ?)",
                  (username, generate_password_hash(password), email, phone, 'company'))
        user_id = c.lastrowid
        c.execute("INSERT INTO companies (user_id, company_name, address, website, field, country) VALUES (?, ?, ?, ?, ?, ?)",
                  (user_id, company_name, address, website, field, country))
        conn.commit()
        return jsonify({'message': 'Company registered successfully'}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'message': f'Registration failed: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/jobs', methods=['GET'])
def api_get_jobs():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT j.*, c.company_name FROM jobs j JOIN companies c ON j.company_id = c.user_id ORDER BY j.created_at DESC")
    jobs = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({'jobs': jobs}), 200

@app.route('/api/jobs', methods=['POST'])
@token_required(role='company')
def api_post_job(current_user, user_role):
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    requirements = data.get('requirements')
    salary = data.get('salary')
    address = data.get('address')
    education = data.get('education', '')
    experience = data.get('experience', '')
    created_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not all([title, description, requirements, salary, address]):
        return jsonify({'message': 'Missing required fields'}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO jobs (company_id, title, description, requirements, salary, address, education, experience, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (current_user, title, description, requirements, salary, address, education, experience, created_at))
        conn.commit()
        return jsonify({'message': 'Job posted successfully'}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'message': f'Failed to post job: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/jobs/<int:job_id>', methods=['PUT'])
@token_required(role='company')
def api_edit_job(current_user, user_role, job_id):
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    requirements = data.get('requirements')
    salary = data.get('salary')
    address = data.get('address')
    education = data.get('education', '')
    experience = data.get('experience', '')

    if not all([title, description, requirements, salary, address]):
        return jsonify({'message': 'Missing required fields'}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM jobs WHERE id = ? AND company_id = ?", (job_id, current_user))
    job = c.fetchone()

    if not job:
        conn.close()
        return jsonify({'message': 'Job not found or unauthorized'}), 404

    try:
        c.execute("UPDATE jobs SET title = ?, description = ?, requirements = ?, salary = ?, address = ?, education = ?, experience = ? WHERE id = ?",
                  (title, description, requirements, salary, address, education, experience, job_id))
        conn.commit()
        return jsonify({'message': 'Job updated successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'message': f'Failed to update job: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/jobs/<int:job_id>', methods=['DELETE'])
@token_required(role='company')
def api_delete_job(current_user, user_role, job_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM jobs WHERE id = ? AND company_id = ?", (job_id, current_user))
    job = c.fetchone()

    if not job:
        conn.close()
        return jsonify({'message': 'Job not found or unauthorized'}), 404

    try:
        c.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        conn.commit()
        return jsonify({'message': 'Job deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'message': f'Failed to delete job: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/jobs/<int:job_id>/apply', methods=['POST'])
@token_required(role='candidate')
def api_apply_job(current_user, user_role, job_id):
    data = request.get_json()
    cover_letter = data.get('cover_letter', '')
    created_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
    job = c.fetchone()

    if not job:
        conn.close()
        return jsonify({'message': 'Job not found'}), 404

    try:
        c.execute("INSERT INTO applications (job_id, candidate_id, cover_letter, applied_at) VALUES (?, ?, ?, ?)",
                  (job_id, current_user, cover_letter, created_at))
        conn.commit()
        return jsonify({'message': 'Application submitted successfully'}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'message': f'Failed to apply: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/users', methods=['GET'])
@token_required(role='admin')
def api_get_users(current_user, user_role):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT u.*, c.full_name, co.company_name FROM users u LEFT JOIN candidates c ON u.id = c.user_id LEFT JOIN companies co ON u.id = co.user_id WHERE u.role != 'admin'")
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({'users': users}), 200

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required(role='admin')
def api_delete_user(current_user, user_role, user_id):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        if c.rowcount == 0:
            conn.close()
            return jsonify({'message': 'User not found or unauthorized'}), 404
        conn.commit()
        return jsonify({'message': 'User deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'message': f'Failed to delete user: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/posts', methods=['GET'])
@token_required(role='admin')
def api_get_posts(current_user, user_role):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT j.*, c.company_name FROM jobs j JOIN companies c ON j.company_id = c.user_id")
    jobs = [dict(row) for row in c.fetchall()]
    c.execute("SELECT js.*, c.full_name FROM job_seeks js JOIN candidates c ON js.candidate_id = c.user_id")
    job_seeks = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({'jobs': jobs, 'job_seeks': job_seeks}), 200

@app.route('/api/posts/<string:post_type>/<int:post_id>', methods=['DELETE'])
@token_required(role='admin')
def api_delete_post(current_user, user_role, post_type, post_id):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        if post_type == 'job':
            c.execute("DELETE FROM jobs WHERE id = ?", (post_id,))
        elif post_type == 'job_seek':
            c.execute("DELETE FROM job_seeks WHERE id = ?", (post_id,))
        else:
            conn.close()
            return jsonify({'message': 'Invalid post type'}), 400
        if c.rowcount == 0:
            conn.close()
            return jsonify({'message': 'Post not found'}), 404
        conn.commit()
        return jsonify({'message': f'{post_type.capitalize()} deleted successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'message': f'Failed to delete post: {str(e)}'}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)