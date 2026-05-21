# ============================================================
# app.py — UPGRADED with Login, Roles, Edit, Charts
# ============================================================

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
# werkzeug comes with Flask — it safely hashes passwords so they're not stored as plain text
from datetime import datetime
from functools import wraps   # needed to build login decorators
import json                   # to send chart data to HTML

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'sams-super-secret-key-2024'
# secret_key is required for sessions (login state) to work. Keep this private!

db = SQLAlchemy(app)


# ============================================================
# DATABASE MODELS
# ============================================================

class User(db.Model):
    """Stores all users: admin, teachers, and students."""
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(80), unique=True, nullable=False)
    password   = db.Column(db.String(200), nullable=False)  # stored as a hash, never plain text
    role       = db.Column(db.String(20), nullable=False)   # 'admin', 'teacher', 'student'
    full_name  = db.Column(db.String(100), nullable=False)
    email      = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    study_logs = db.relationship('StudyLog', backref='student', lazy=True,
                                 foreign_keys='StudyLog.student_id', cascade='all, delete-orphan')
    results    = db.relationship('Result', backref='student', lazy=True,
                                 foreign_keys='Result.student_id', cascade='all, delete-orphan')


class Subject(db.Model):
    """Each subject is linked to a teacher."""
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    teacher    = db.relationship('User', foreign_keys=[teacher_id])
    study_logs = db.relationship('StudyLog', backref='subject', lazy=True, cascade='all, delete-orphan')
    results    = db.relationship('Result',   backref='subject', lazy=True, cascade='all, delete-orphan')


class StudyLog(db.Model):
    """Tracks how long a student studied a subject."""
    id         = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    date       = db.Column(db.Date, nullable=False)
    hours      = db.Column(db.Float, nullable=False)
    notes      = db.Column(db.String(300))


class Result(db.Model):
    """Stores exam results — added by teachers for students."""
    id             = db.Column(db.Integer, primary_key=True)
    student_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject_id     = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    exam_name      = db.Column(db.String(100), nullable=False)
    marks_obtained = db.Column(db.Float, nullable=False)
    total_marks    = db.Column(db.Float, nullable=False)
    date           = db.Column(db.Date, nullable=False)

    @property
    def percentage(self):
        return round((self.marks_obtained / self.total_marks) * 100, 1)

    @property
    def grade(self):
        p = self.percentage
        if p >= 90: return 'A+'
        elif p >= 80: return 'A'
        elif p >= 70: return 'B'
        elif p >= 60: return 'C'
        elif p >= 50: return 'D'
        else:        return 'F'


# ============================================================
# DECORATORS — used to protect routes based on login/role
# A decorator wraps a function to add extra behavior.
# ============================================================

def login_required(f):
    """Redirects to login page if not logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Only admins can access this route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admins only.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def teacher_or_admin(f):
    """Only teachers and admins can access this route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') not in ['admin', 'teacher']:
            flash('Access denied. Teachers only.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))  # already logged in

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # Store user info in session (like a temporary cookie)
            session['user_id']   = user.id
            session['username']  = user.username
            session['role']      = user.role
            session['full_name'] = user.full_name
            flash(f'Welcome back, {user.full_name}! 👋', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ============================================================
# DASHBOARD (Home Page) — different content per role
# ============================================================

@app.route('/')
@login_required
def index():
    role    = session['role']
    user_id = session['user_id']

    if role == 'admin':
        stats = {
            'students': User.query.filter_by(role='student').count(),
            'teachers': User.query.filter_by(role='teacher').count(),
            'subjects': Subject.query.count(),
            'results':  Result.query.count(),
        }
        recent_results = Result.query.order_by(Result.date.desc()).limit(6).all()
        subjects = Subject.query.all()
        chart_labels = json.dumps([s.name for s in subjects])
        chart_data   = json.dumps([Result.query.filter_by(subject_id=s.id).count() for s in subjects])
        return render_template('index.html', role=role, stats=stats,
                               recent_results=recent_results,
                               chart_labels=chart_labels, chart_data=chart_data)

    elif role == 'teacher':
        my_subjects    = Subject.query.filter_by(teacher_id=user_id).all()
        recent_results = (Result.query.join(Subject)
                          .filter(Subject.teacher_id == user_id)
                          .order_by(Result.date.desc()).limit(6).all())
        stats = {
            'subjects': len(my_subjects),
            'results':  Result.query.join(Subject).filter(Subject.teacher_id == user_id).count(),
            'students': len(set(r.student_id for r in recent_results)),
        }
        chart_labels = json.dumps([s.name for s in my_subjects])
        chart_data   = json.dumps([Result.query.filter_by(subject_id=s.id).count() for s in my_subjects])
        return render_template('index.html', role=role, stats=stats,
                               my_subjects=my_subjects, recent_results=recent_results,
                               chart_labels=chart_labels, chart_data=chart_data)

    else:  # student
        my_results  = Result.query.filter_by(student_id=user_id).order_by(Result.date.desc()).all()
        my_logs     = StudyLog.query.filter_by(student_id=user_id).all()
        total_hours = round(sum(log.hours for log in my_logs), 1)
        stats = {
            'results': len(my_results),
            'hours':   total_hours,
            'subjects': len(set(r.subject_id for r in my_results)),
        }
        chart_labels = json.dumps([f"{r.subject.name}" for r in my_results])
        chart_data   = json.dumps([r.percentage for r in my_results])
        return render_template('index.html', role=role, stats=stats,
                               my_results=my_results, total_hours=total_hours,
                               chart_labels=chart_labels, chart_data=chart_data)


# ============================================================
# ADMIN — Manage Users
# ============================================================

@app.route('/admin')
@admin_required
def admin():
    students = User.query.filter_by(role='student').order_by(User.full_name).all()
    teachers = User.query.filter_by(role='teacher').order_by(User.full_name).all()
    return render_template('admin.html', students=students, teachers=teachers)


@app.route('/admin/add_user', methods=['POST'])
@admin_required
def add_user():
    username  = request.form['username'].strip()
    password  = request.form['password']
    role      = request.form['role']
    full_name = request.form['full_name'].strip()
    email     = request.form.get('email', '').strip()

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" is already taken. Choose another.', 'danger')
        return redirect(url_for('admin'))

    new_user = User(
        username=username,
        password=generate_password_hash(password),
        role=role,
        full_name=full_name,
        email=email
    )
    db.session.add(new_user)
    db.session.commit()
    flash(f'✅ {role.capitalize()} account for "{full_name}" created! Username: {username}', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/delete_user/<int:id>')
@admin_required
def delete_user(id):
    user = User.query.get_or_404(id)
    if user.role == 'admin':
        flash('Cannot delete the admin account.', 'danger')
        return redirect(url_for('admin'))
    name = user.full_name
    db.session.delete(user)
    db.session.commit()
    flash(f'Account for "{name}" deleted.', 'success')
    return redirect(url_for('admin'))


# ============================================================
# SUBJECTS
# ============================================================

@app.route('/subjects', methods=['GET', 'POST'])
@login_required
def subjects():
    role = session['role']
    if request.method == 'POST' and role in ['admin', 'teacher']:
        name = request.form['name'].strip()
        teacher_id = session['user_id'] if role == 'teacher' else (request.form.get('teacher_id') or None)
        db.session.add(Subject(name=name, teacher_id=teacher_id))
        db.session.commit()
        flash('Subject added!', 'success')
        return redirect(url_for('subjects'))

    all_subjects = Subject.query.all()
    teachers     = User.query.filter_by(role='teacher').all()
    return render_template('subjects.html', subjects=all_subjects, teachers=teachers, role=role)


@app.route('/edit_subject/<int:id>', methods=['GET', 'POST'])
@teacher_or_admin
def edit_subject(id):
    subject  = Subject.query.get_or_404(id)
    teachers = User.query.filter_by(role='teacher').all()
    if request.method == 'POST':
        subject.name = request.form['name'].strip()
        if session['role'] == 'admin':
            subject.teacher_id = request.form.get('teacher_id') or None
        db.session.commit()
        flash('Subject updated!', 'success')
        return redirect(url_for('subjects'))
    return render_template('edit_subject.html', subject=subject, teachers=teachers, role=session['role'])


@app.route('/delete_subject/<int:id>')
@teacher_or_admin
def delete_subject(id):
    subject = Subject.query.get_or_404(id)
    db.session.delete(subject)
    db.session.commit()
    flash('Subject deleted.', 'success')
    return redirect(url_for('subjects'))


# ============================================================
# STUDY LOG
# ============================================================

@app.route('/study_log', methods=['GET', 'POST'])
@login_required
def study_log():
    role    = session['role']
    user_id = session['user_id']

    if request.method == 'POST':
        sid = user_id if role == 'student' else request.form.get('student_id', user_id)
        log = StudyLog(
            student_id = sid,
            subject_id = request.form['subject_id'],
            date       = datetime.strptime(request.form['date'], '%Y-%m-%d').date(),
            hours      = float(request.form['hours']),
            notes      = request.form.get('notes', '')
        )
        db.session.add(log)
        db.session.commit()
        flash('Study session logged!', 'success')
        return redirect(url_for('study_log'))

    subjects = Subject.query.all()
    students = User.query.filter_by(role='student').all()
    logs     = (StudyLog.query.filter_by(student_id=user_id) if role == 'student'
                else StudyLog.query).order_by(StudyLog.date.desc()).all()
    return render_template('study_log.html', subjects=subjects, logs=logs, role=role, students=students)


@app.route('/edit_log/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_log(id):
    log      = StudyLog.query.get_or_404(id)
    subjects = Subject.query.all()
    students = User.query.filter_by(role='student').all()
    if request.method == 'POST':
        log.subject_id = request.form['subject_id']
        log.date  = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        log.hours = float(request.form['hours'])
        log.notes = request.form.get('notes', '')
        db.session.commit()
        flash('Study session updated!', 'success')
        return redirect(url_for('study_log'))
    return render_template('edit_log.html', log=log, subjects=subjects, students=students)


@app.route('/delete_log/<int:id>')
@login_required
def delete_log(id):
    log = StudyLog.query.get_or_404(id)
    db.session.delete(log)
    db.session.commit()
    flash('Study session deleted.', 'success')
    return redirect(url_for('study_log'))


# ============================================================
# RESULTS
# ============================================================

@app.route('/results', methods=['GET', 'POST'])
@login_required
def results():
    role    = session['role']
    user_id = session['user_id']

    if request.method == 'POST' and role in ['admin', 'teacher']:
        result = Result(
            student_id     = request.form['student_id'],
            subject_id     = request.form['subject_id'],
            exam_name      = request.form['exam_name'].strip(),
            marks_obtained = float(request.form['marks_obtained']),
            total_marks    = float(request.form['total_marks']),
            date           = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        )
        db.session.add(result)
        db.session.commit()
        flash('Result saved!', 'success')
        return redirect(url_for('results'))

    subjects     = Subject.query.all()
    students     = User.query.filter_by(role='student').all()
    all_results  = (Result.query.filter_by(student_id=user_id) if role == 'student'
                    else Result.query).order_by(Result.date.desc()).all()
    return render_template('results.html', subjects=subjects, students=students,
                           results=all_results, role=role)


@app.route('/edit_result/<int:id>', methods=['GET', 'POST'])
@teacher_or_admin
def edit_result(id):
    result   = Result.query.get_or_404(id)
    subjects = Subject.query.all()
    students = User.query.filter_by(role='student').all()
    if request.method == 'POST':
        result.student_id     = request.form['student_id']
        result.subject_id     = request.form['subject_id']
        result.exam_name      = request.form['exam_name'].strip()
        result.marks_obtained = float(request.form['marks_obtained'])
        result.total_marks    = float(request.form['total_marks'])
        result.date           = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        db.session.commit()
        flash('Result updated!', 'success')
        return redirect(url_for('results'))
    return render_template('edit_result.html', result=result, subjects=subjects, students=students)


@app.route('/delete_result/<int:id>')
@teacher_or_admin
def delete_result(id):
    result = Result.query.get_or_404(id)
    db.session.delete(result)
    db.session.commit()
    flash('Result deleted.', 'success')
    return redirect(url_for('results'))


# ============================================================
# RUN
# ============================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Auto-create default admin account on first run
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username  = 'admin',
                password  = generate_password_hash('admin123'),
                role      = 'admin',
                full_name = 'Administrator',
                email     = 'admin@sams.com'
            )
            db.session.add(admin_user)
            db.session.commit()
            print('✅ Default admin created → username: admin | password: admin123')
    app.run(debug=True)