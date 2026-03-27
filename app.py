import os
import csv
import secrets
from datetime import datetime, timedelta
from functools import wraps
from io import StringIO
from shutil import disk_usage

from flask import Flask, render_template, request, redirect, url_for, session, Response
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from models import db, User, Admin, Scan, AuditLog, SystemConfig, Notification, Feedback

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('VISCANE_SECRET_KEY', 'change-this-key')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///viscane.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    except Exception:
        pass

with app.app_context():
    db.create_all()

    # SQLite doesn't auto-migrate. If the admin table exists from an older
    # version, add the role column if it's missing.
    try:
        columns = [
            row[1] for row in db.session.execute(db.text("PRAGMA table_info(admin)"))
        ]
        if "role" not in columns:
            db.session.execute(
                db.text("ALTER TABLE admin ADD COLUMN role VARCHAR(40) NOT NULL DEFAULT 'admin'")
            )
            db.session.commit()
        if "is_archived" not in columns:
            db.session.execute(
                db.text("ALTER TABLE admin ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT 0")
            )
            db.session.commit()
    except Exception:
        db.session.rollback()

    try:
        user_columns = [
            row[1] for row in db.session.execute(db.text("PRAGMA table_info(user)"))
        ]
        if "province" not in user_columns:
            db.session.execute(
                db.text("ALTER TABLE user ADD COLUMN province VARCHAR(120)")
            )
            db.session.commit()
        if "municipality" not in user_columns:
            db.session.execute(
                db.text("ALTER TABLE user ADD COLUMN municipality VARCHAR(120)")
            )
            db.session.commit()
        if "barangay" not in user_columns:
            db.session.execute(
                db.text("ALTER TABLE user ADD COLUMN barangay VARCHAR(120)")
            )
            db.session.commit()
        if "is_active" not in user_columns:
            db.session.execute(
                db.text("ALTER TABLE user ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1")
            )
            db.session.commit()
        if "is_archived" not in user_columns:
            db.session.execute(
                db.text("ALTER TABLE user ADD COLUMN is_archived BOOLEAN NOT NULL DEFAULT 0")
            )
            db.session.commit()
    except Exception:
        db.session.rollback()

    try:
        config_columns = [
            row[1] for row in db.session.execute(db.text("PRAGMA table_info(system_config)"))
        ]
        if "model_filename" not in config_columns:
            db.session.execute(
                db.text("ALTER TABLE system_config ADD COLUMN model_filename VARCHAR(255)")
            )
            db.session.commit()
    except Exception:
        db.session.rollback()

    try:
        if not SystemConfig.query.first():
            db.session.add(SystemConfig(system_name='CaneDustry', maintenance_mode=False))
            db.session.commit()
    except Exception:
        db.session.rollback()

    # Ensure scan table has ON DELETE CASCADE for user_id
    try:
        fk_rows = db.session.execute(text("PRAGMA foreign_key_list(scan)")).fetchall()
        needs_cascade = True
        for row in fk_rows:
            # row tuple: (id, seq, table, from, to, on_update, on_delete, match)
            if row[2] == "user" and row[3] == "user_id" and str(row[6]).lower() == "cascade":
                needs_cascade = False
                break
        if needs_cascade and fk_rows:
            db.session.execute(text("PRAGMA foreign_keys=OFF"))
            db.session.execute(text("ALTER TABLE scan RENAME TO scan_old"))
            db.session.execute(text("""
                CREATE TABLE scan (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    plot_name VARCHAR(80) NOT NULL,
                    grade VARCHAR(2) NOT NULL,
                    maturity_pct INTEGER NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    created_at DATETIME NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES user (id) ON DELETE CASCADE
                )
            """))
            db.session.execute(text("""
                INSERT INTO scan (id, user_id, plot_name, grade, maturity_pct, status, created_at)
                SELECT id, user_id, plot_name, grade, maturity_pct, status, created_at
                FROM scan_old
            """))
            db.session.execute(text("DROP TABLE scan_old"))
            db.session.execute(text("PRAGMA foreign_keys=ON"))
            db.session.commit()
    except Exception:
        db.session.rollback()

def farmer_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('auth', mode='login'))
        user = User.query.get(session.get('user_id'))
        if not user or user.is_archived or not user.is_active:
            session.pop('user_id', None)
            return redirect(url_for('auth', mode='login'))
        return view(*args, **kwargs)
    return wrapped

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('admin_id'):
            return redirect(url_for('admin_login'))
        return view(*args, **kwargs)
    return wrapped

def role_required(required_role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            admin_id = session.get('admin_id')
            if not admin_id:
                return redirect(url_for('admin_login'))
            admin = Admin.query.get(admin_id)
            if not admin or admin.is_archived or admin.role != required_role:
                return redirect(url_for('admin_portal'))
            return view(*args, **kwargs)
        return wrapped
    return decorator

def get_current_admin():
    admin_id = session.get('admin_id')
    if not admin_id:
        return None
    admin = Admin.query.get(admin_id)
    if not admin or admin.is_archived:
        return None
    return admin

def log_audit(action, user_id=None):
    try:
        entry = AuditLog(user_id=user_id, action=action)
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

def get_system_config():
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig(system_name='VISCANE', maintenance_mode=False)
        db.session.add(config)
        db.session.commit()
    return config

def estimate_scan_metrics(scan):
    maturity = scan.maturity_pct or 0
    estimated_tch = round(40 + (maturity * 0.6), 2)
    estimated_lkg_tc = round(1.5 + (maturity * 0.01), 2)
    estimated_trash_pct = round(max(2, 12 - (maturity * 0.08)), 2)
    return estimated_tch, estimated_lkg_tc, estimated_trash_pct

def verify_and_upgrade_password(user, raw_password):
    try:
        if check_password_hash(user.password, raw_password):
            return True
    except Exception:
        pass
    if user.password == raw_password:
        user.password = generate_password_hash(raw_password)
        db.session.commit()
        return True
    return False

@app.route('/')
def portal():
    # The Welcome Page
    return render_template('portal.html')

@app.route('/homepage')
@farmer_login_required
def homepage():
    # Farmer Dashboard
    user = User.query.get(session.get('user_id'))
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('auth', mode='login'))

    if not Scan.query.filter_by(user_id=user.id).first():
        sample_scans = [
            Scan(user_id=user.id, plot_name='Plot #4 Sample', grade='A', maturity_pct=91, status='ready', created_at=datetime.utcnow() - timedelta(hours=2)),
            Scan(user_id=user.id, plot_name='Plot #2 Sample', grade='B', maturity_pct=76, status='monitor', created_at=datetime.utcnow() - timedelta(hours=3)),
            Scan(user_id=user.id, plot_name='Plot #1 Sample', grade='A', maturity_pct=88, status='healthy', created_at=datetime.utcnow() - timedelta(days=1)),
        ]
        db.session.add_all(sample_scans)
        db.session.commit()

    today = datetime.utcnow().date()
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    scans_today = Scan.query.filter(Scan.user_id == user.id, Scan.created_at >= datetime(today.year, today.month, today.day)).count()
    pending_scans = Scan.query.filter(Scan.user_id == user.id, Scan.status == 'pending').count()
    scans_last7 = Scan.query.filter(Scan.user_id == user.id, Scan.created_at >= seven_days_ago).all()
    recent_scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).limit(3).all()

    if scans_last7:
        grade_a = sum(1 for s in scans_last7 if s.grade.upper() == 'A')
        avg_grade_a = int((grade_a / len(scans_last7)) * 100)
        avg_maturity = int(sum(s.maturity_pct for s in scans_last7) / len(scans_last7))
    else:
        avg_grade_a = 0
        avg_maturity = 0

    if avg_maturity >= 85:
        yield_est = "High"
        harvest_window = "3-7 days"
    elif avg_maturity >= 75:
        yield_est = "Medium"
        harvest_window = "8-12 days"
    else:
        yield_est = "Low"
        harvest_window = "14-18 days"

    return render_template(
        'homepage.html',
        user=user,
        scans_today=scans_today,
        pending_scans=pending_scans,
        avg_grade_a=avg_grade_a,
        yield_est=yield_est,
        harvest_window=harvest_window,
        avg_maturity=avg_maturity,
        recent_scans=recent_scans
    )

@app.route('/calculate', methods=['POST'])
@farmer_login_required
def calculate_results():
    user = User.query.get(session.get('user_id'))
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('auth', mode='login'))

    variety = request.form.get('variety', '').strip()
    plowing_count = request.form.get('plowing_count', '').strip()
    weeding_count = request.form.get('weeding_count', '').strip()
    rssi_infected = request.form.get('rssi_infected', '').strip()
    tons_per_hectare = request.form.get('tons_per_hectare', '').strip()

    latest_scan = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).first()
    maturity_pct = latest_scan.maturity_pct if latest_scan else None

    variety_display = variety or 'Not provided'
    maturity_display = f"{maturity_pct}%" if maturity_pct is not None else 'Not provided'
    tch_display = tons_per_hectare if tons_per_hectare else 'Not provided'
    lkg_tc_display = 'Pending'
    predicted_lkg_tc_display = 'Pending'

    return render_template(
        'calculate_results.html',
        user=user,
        variety_display=variety_display,
        maturity_display=maturity_display,
        lkg_tc_display=lkg_tc_display,
        tch_display=tch_display,
        predicted_lkg_tc_display=predicted_lkg_tc_display,
        plowing_count=plowing_count,
        weeding_count=weeding_count,
        rssi_infected=rssi_infected
    )

@app.route('/admin')
@login_required
def admin_portal():
    # Admin Dashboard
    current_admin = get_current_admin()
    total_users = User.query.filter_by(is_archived=False, is_active=True).count()
    total_scans = Scan.query.count()
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    active_user_ids = db.session.query(User.id).filter(
        User.is_archived.is_(False),
        User.is_active.is_(True)
    ).subquery()
    active_farmers = db.session.query(Scan.user_id).filter(
        Scan.created_at >= seven_days_ago,
        Scan.user_id.in_(active_user_ids)
    ).distinct().count()
    pending_reviews = Scan.query.filter(
        Scan.status == 'pending',
        Scan.user_id.in_(active_user_ids)
    ).count()
    users = User.query.filter_by(is_archived=False, is_active=True).order_by(User.id.desc()).limit(6).all()
    logs = [
        {"icon": "server-outline", "title": "Database Backup", "meta": "Completed 1 hour ago", "status": "Success", "color": "#2E7D32"},
        {"icon": "warning-outline", "title": "Failed Login Attempt", "meta": "IP: 192.168.1.45 | 2 hrs ago", "status": "Alert", "color": "#C62828"},
        {"icon": "person-add-outline", "title": "New User Registration", "meta": "Maria Santos | 4 hrs ago", "status": "Review", "color": "#1565C0"},
    ]
    model_accuracy = 98.6
    storage_utilization = 68
    try:
        usage = disk_usage(os.getcwd())
        if usage.total > 0:
            storage_utilization = round((usage.used / usage.total) * 100, 1)
    except Exception:
        pass
    stats = {
        "active_users": total_users,
        "total_scans": total_scans,
        "model_accuracy": model_accuracy,
        "storage_utilization": storage_utilization,
    }
    return render_template(
        'admin.html',
        total_users=total_users,
        active_farmers=active_farmers,
        pending_reviews=pending_reviews,
        users=users,
        logs=logs,
        current_admin=current_admin,
        stats=stats
    )

@app.route('/admin/farmers', methods=['GET', 'POST'])
@login_required
def admin_farmers():
    message = request.args.get('message')
    error = request.args.get('error')

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            fullname = request.form.get('fullname', '').strip()
            email = request.form.get('email', '').strip().lower()
            phone = request.form.get('phone', '').strip()
            province = request.form.get('province', '').strip()
            municipality = request.form.get('municipality', '').strip()
            barangay = request.form.get('barangay', '').strip()
            password = request.form.get('password', '').strip()
            if not fullname or not email or not phone or not password:
                return redirect(url_for('admin_farmers', error='Please complete all required fields.'))
            if User.query.filter_by(email=email).first():
                return redirect(url_for('admin_farmers', error='Email already exists.'))
            new_user = User(
                fullname=fullname,
                email=email,
                phone=phone,
                password=generate_password_hash(password),
                province=province,
                municipality=municipality,
                barangay=barangay,
                is_active=True,
                is_archived=False
            )
            db.session.add(new_user)
            db.session.commit()
            log_audit(f"Admin created farmer account: {fullname}", user_id=get_current_admin().id if get_current_admin() else None)
            return redirect(url_for('admin_farmers', message='Farmer account created successfully.'))

        if action == 'deactivate':
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user and not user.is_archived:
                user.is_active = False
                db.session.commit()
                log_audit(f"Farmer account deactivated: {user.fullname}", user_id=get_current_admin().id if get_current_admin() else None)
            return redirect(url_for('admin_farmers'))

        if action == 'activate':
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user and not user.is_archived:
                user.is_active = True
                db.session.commit()
                log_audit(f"Farmer account reactivated: {user.fullname}", user_id=get_current_admin().id if get_current_admin() else None)
            return redirect(url_for('admin_farmers'))

        if action == 'reset':
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user and not user.is_archived:
                temp_password = f"Temp{secrets.randbelow(100000):05d}"
                user.password = generate_password_hash(temp_password)
                db.session.commit()
                log_audit(f"Farmer credentials reset: {user.fullname}", user_id=get_current_admin().id if get_current_admin() else None)
                return redirect(url_for('admin_farmers', message=f"Temporary password for {user.fullname}: {temp_password}"))
            return redirect(url_for('admin_farmers', error='Unable to reset credentials.'))

    users = User.query.filter_by(is_archived=False).order_by(User.id.desc()).all()
    return render_template('admin_farmers.html', users=users, message=message, error=error, current_admin=get_current_admin())

@app.route('/admin/farmers/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_farmer_edit(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_archived:
        return redirect(url_for('admin_farmers'))

    if request.method == 'POST':
        user.fullname = request.form.get('fullname', '').strip()
        user.email = request.form.get('email', '').strip().lower()
        user.phone = request.form.get('phone', '').strip()
        user.province = request.form.get('province', '').strip()
        user.municipality = request.form.get('municipality', '').strip()
        user.barangay = request.form.get('barangay', '').strip()
        db.session.commit()
        log_audit(f"Farmer account updated: {user.fullname}", user_id=get_current_admin().id if get_current_admin() else None)
        return redirect(url_for('admin_farmers', message='Farmer account updated.'))

    return render_template('admin_farmer_edit.html', user=user, current_admin=get_current_admin())

@app.route('/admin/monitoring')
@login_required
def admin_monitoring():
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(50).all()
    monitoring_rows = []
    for scan in scans:
        tch, lkg_tc, _ = estimate_scan_metrics(scan)
        bags = round(tch * 20, 2)
        monitoring_rows.append({
            "plot_name": scan.plot_name,
            "grade": scan.grade,
            "maturity_pct": scan.maturity_pct,
            "status": scan.status,
            "tch": tch,
            "lkg_tc": lkg_tc,
            "bags": bags,
            "created_at": scan.created_at
        })
    return render_template('admin_monitoring.html', rows=monitoring_rows, current_admin=get_current_admin())

@app.route('/admin/models', methods=['GET', 'POST'])
@login_required
def admin_models():
    config = get_system_config()
    message = None
    if request.method == 'POST':
        model_file = request.files.get('model_file')
        if model_file and model_file.filename:
            filename = secure_filename(model_file.filename)
            target_dir = os.path.join(app.root_path, 'model_updates')
            os.makedirs(target_dir, exist_ok=True)
            file_path = os.path.join(target_dir, filename)
            model_file.save(file_path)
            config.model_filename = filename
            db.session.commit()
            log_audit(f"Model update received: {filename}", user_id=get_current_admin().id if get_current_admin() else None)
            message = f"Model '{filename}' uploaded successfully."
    return render_template('admin_models.html', config=config, message=message, current_admin=get_current_admin())

@app.route('/admin/reports')
@login_required
def admin_reports():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    farmer_summary = {}
    for scan in scans:
        tch, lkg_tc, _ = estimate_scan_metrics(scan)
        entry = farmer_summary.setdefault(scan.user_id, {
            "count": 0,
            "total_maturity": 0,
            "total_tch": 0,
            "total_lkg_tc": 0
        })
        entry["count"] += 1
        entry["total_maturity"] += scan.maturity_pct
        entry["total_tch"] += tch
        entry["total_lkg_tc"] += lkg_tc

    rows = []
    for user_id, summary in farmer_summary.items():
        user = User.query.get(user_id)
        if not user or user.is_archived:
            continue
        count = summary["count"]
        rows.append({
            "name": user.fullname,
            "municipality": user.municipality or 'N/A',
            "barangay": user.barangay or 'N/A',
            "scans": count,
            "avg_maturity": round(summary["total_maturity"] / count, 1) if count else 0,
            "avg_tch": round(summary["total_tch"] / count, 2) if count else 0,
            "avg_lkg_tc": round(summary["total_lkg_tc"] / count, 2) if count else 0
        })

    rows = sorted(rows, key=lambda item: item["scans"], reverse=True)
    return render_template('admin_reports.html', rows=rows, current_admin=get_current_admin())

@app.route('/admin/communications', methods=['GET', 'POST'])
@login_required
def admin_communications():
    message = None
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('message', '').strip()
        if title and content:
            notification = Notification(
                title=title,
                message=content,
                created_by=get_current_admin().id if get_current_admin() else None
            )
            db.session.add(notification)
            db.session.commit()
            log_audit(f"Announcement published: {title}", user_id=get_current_admin().id if get_current_admin() else None)
            message = 'Announcement published.'

    notifications = Notification.query.order_by(Notification.created_at.desc()).limit(10).all()
    feedback = Feedback.query.order_by(Feedback.created_at.desc()).limit(20).all()
    return render_template(
        'admin_communications.html',
        notifications=notifications,
        feedback=feedback,
        message=message,
        current_admin=get_current_admin()
    )

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if not Admin.query.filter_by(is_archived=False).first():
        return redirect(url_for('admin_setup'))
    error = None
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip().lower()
        password = request.form.get('password', '')
        admin = Admin.query.filter(
            ((Admin.username.ilike(identifier)) | (Admin.email.ilike(identifier))) & (Admin.is_archived.is_(False))
        ).first()
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_id'] = admin.id
            return redirect(url_for('admin_portal'))
        error = 'Invalid admin credentials. Please try again.'
    return render_template('admin_login.html', error=error)

@app.route('/superadmin-login', methods=['GET', 'POST'])
def superadmin_login():
    if not Admin.query.filter_by(is_archived=False).first():
        return redirect(url_for('admin_setup'))
    error = None
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip().lower()
        password = request.form.get('password', '')
        admin = Admin.query.filter(
            ((Admin.username.ilike(identifier)) | (Admin.email.ilike(identifier))) & (Admin.is_archived.is_(False))
        ).first()
        if admin and check_password_hash(admin.password_hash, password):
            if admin.role != 'superadmin':
                error = 'Your account is not authorized for superadmin access.'
            else:
                session['admin_id'] = admin.id
                return redirect(url_for('superadmin_portal'))
        else:
            error = 'Invalid superadmin credentials. Please try again.'
    return render_template('superadmin_login.html', error=error)

@app.route('/admin-setup', methods=['GET', 'POST'])
def admin_setup():
    if Admin.query.filter_by(is_archived=False).first():
        return redirect(url_for('admin_login'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if not username or not email or not password:
            error = 'Please complete all fields.'
        elif password != confirm:
            error = 'Passwords do not match.'
        else:
            admin = Admin(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role='superadmin'
            )
            db.session.add(admin)
            db.session.commit()
            session['admin_id'] = admin.id
            log_audit(f"Superadmin account created: {admin.username}", user_id=admin.id)
            return redirect(url_for('admin_portal'))
    return render_template('admin_setup.html', error=error)

@app.route('/admin-reset', methods=['GET', 'POST'])
def admin_reset():
    error = None
    success = None
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        new_password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if new_password != confirm:
            error = 'Passwords do not match.'
        else:
            admin = Admin.query.filter(
                (Admin.username.ilike(identifier)) | (Admin.email.ilike(identifier))
            ).first()
            if not admin or admin.email.lower() != email:
                error = 'Admin account not found with those details.'
            else:
                admin.password_hash = generate_password_hash(new_password)
                db.session.commit()
                success = 'Password updated. You can sign in now.'
    return render_template('admin_reset.html', error=error, success=success)

@app.route('/superadmin')
@role_required('superadmin')
def superadmin_portal():
    total_users = User.query.filter_by(is_archived=False).count()
    total_admins = Admin.query.filter_by(is_archived=False).count()
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    active_user_ids = db.session.query(User.id).filter(User.is_archived.is_(False)).subquery()
    active_farmers = db.session.query(Scan.user_id).filter(
        Scan.created_at >= seven_days_ago,
        Scan.user_id.in_(active_user_ids)
    ).distinct().count()
    total_scans = Scan.query.count()
    pending_scans = Scan.query.filter(
        Scan.status == 'pending',
        Scan.user_id.in_(active_user_ids)
    ).count()
    admins = Admin.query.filter_by(is_archived=False).order_by(Admin.id.desc()).all()
    users = User.query.filter_by(is_archived=False).order_by(User.id.desc()).limit(8).all()
    recent_scans = Scan.query.filter(Scan.user_id.in_(active_user_ids)).order_by(Scan.created_at.desc()).limit(6).all()
    return render_template(
        'superadmin.html',
        total_users=total_users,
        total_admins=total_admins,
        active_farmers=active_farmers,
        total_scans=total_scans,
        pending_scans=pending_scans,
        admins=admins,
        users=users,
        recent_scans=recent_scans,
        current_admin=get_current_admin()
    )

@app.route('/superadmin/admins/role', methods=['POST'])
@role_required('superadmin')
def superadmin_update_role():
    admin_id = request.form.get('admin_id')
    role = request.form.get('role', 'admin')
    current_admin = get_current_admin()
    admin = Admin.query.get(admin_id)
    if admin and not admin.is_archived and current_admin and admin.id != current_admin.id:
        admin.role = role
        db.session.commit()
        log_audit(f"Admin role updated for {admin.username} to {role}", user_id=current_admin.id)
    return redirect(url_for('superadmin_portal'))

@app.route('/superadmin/admins/archive', methods=['POST'])
@role_required('superadmin')
def superadmin_archive_admin():
    admin_id = request.form.get('admin_id')
    current_admin = get_current_admin()
    admin = Admin.query.get(admin_id)
    if admin and current_admin and admin.id != current_admin.id:
        admin.is_archived = True
        db.session.commit()
        log_audit(f"Admin account archived: {admin.username}", user_id=current_admin.id)
    return redirect(url_for('superadmin_portal'))

@app.route('/superadmin/users/archive', methods=['POST'])
@role_required('superadmin')
def superadmin_archive_user():
    user_id = request.form.get('user_id')
    user = User.query.get(user_id)
    if user:
        user.is_archived = True
        db.session.commit()
        log_audit(f"User account archived: {user.fullname}", user_id=user.id)
    return redirect(url_for('superadmin_portal'))

@app.route('/admin-logout')
def admin_logout():
    session.pop('admin_id', None)
    return redirect(url_for('portal'))

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    mode = request.args.get('mode', 'login')
    
    if request.method == 'POST':
        if mode == 'register':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm = request.form.get('confirm_password', '')
            if password != confirm:
                return render_template('auth.html', mode=mode, error='Passwords do not match.')
            existing = User.query.filter_by(email=email).first()
            if existing:
                return render_template('auth.html', mode=mode, error='Email already registered.')
            new_user = User(
                fullname=request.form.get('fullname', '').strip(),
                email=email,
                phone=request.form.get('phone', '').strip(),
                password=generate_password_hash(password),
                province=request.form.get('province', '').strip(),
                municipality=request.form.get('municipality', '').strip(),
                barangay=request.form.get('barangay', '').strip()
            )
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            return redirect(url_for('homepage'))

        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and not user.is_archived and user.is_active and verify_and_upgrade_password(user, password):
            session['user_id'] = user.id
            return redirect(url_for('homepage'))
        if user and user.is_archived:
            return render_template('auth.html', mode=mode, error='Account is archived. Please contact support.')
        if user and not user.is_active:
            return render_template('auth.html', mode=mode, error='Account is deactivated. Please contact support.')
        return render_template('auth.html', mode=mode, error='Invalid credentials. Please try again.')
    
    # Handle HTMX requests for switching forms
    if request.headers.get('HX-Request'):
        return render_template('auth_form.html', mode=mode)
    
    return render_template('auth.html', mode=mode)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('portal'))

@app.route('/scan/new', methods=['GET', 'POST'])
@farmer_login_required
def scan_new():
    error = None
    if request.method == 'POST':
        plot_name = request.form.get('plot_name', '').strip()
        grade = request.form.get('grade', '').strip().upper()
        maturity_pct = request.form.get('maturity_pct', '').strip()
        status = request.form.get('status', 'pending').strip().lower()
        if not plot_name or not grade or not maturity_pct:
            error = 'Please complete all fields.'
        else:
            try:
                maturity_value = int(maturity_pct)
            except ValueError:
                maturity_value = None
            if maturity_value is None or maturity_value < 0 or maturity_value > 100:
                error = 'Maturity must be between 0 and 100.'
            else:
                scan = Scan(
                    user_id=session.get('user_id'),
                    plot_name=plot_name,
                    grade=grade,
                    maturity_pct=maturity_value,
                    status=status
                )
                db.session.add(scan)
                db.session.commit()
                log_audit(f"User {session.get('user_id')} uploaded a scan for {plot_name}", user_id=session.get('user_id'))
                return redirect(url_for('homepage'))
    return render_template('scan_new.html', error=error)

@app.route('/superadmin/settings', methods=['GET', 'POST'])
@role_required('superadmin')
def superadmin_settings():
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig(system_name='CaneDustry', maintenance_mode=False)
        db.session.add(config)
        db.session.commit()

    if request.method == 'POST':
        system_name = request.form.get('system_name', '').strip() or config.system_name
        maintenance_mode = True if request.form.get('maintenance_mode') == 'on' else False
        config.system_name = system_name
        config.maintenance_mode = maintenance_mode
        db.session.commit()
        current_admin = get_current_admin()
        if current_admin:
            log_audit("System settings updated", user_id=current_admin.id)
        return redirect(url_for('superadmin_settings'))

    return render_template('superadmin_settings.html', config=config, current_admin=get_current_admin())

@app.route('/superadmin/reports')
@role_required('superadmin')
def superadmin_reports():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    total_scans = len(scans)
    rows = []
    total_tch = 0
    total_lkg_tc = 0
    for scan in scans:
        tch, lkg_tc, _ = estimate_scan_metrics(scan)
        total_tch += tch
        total_lkg_tc += lkg_tc
        rows.append({
            "plot_name": scan.plot_name,
            "grade": scan.grade,
            "maturity_pct": scan.maturity_pct,
            "tch": tch,
            "lkg_tc": lkg_tc,
            "created_at": scan.created_at
        })

    avg_lkg_tc = round(total_lkg_tc / total_scans, 2) if total_scans else 0
    total_predicted_yield = round(total_tch, 2) if total_scans else 0

    report = {
        "avg_lkg_tc": avg_lkg_tc,
        "total_predicted_yield": total_predicted_yield,
        "total_scans": total_scans
    }

    return render_template(
        'superadmin_reports.html',
        report=report,
        rows=rows,
        current_admin=get_current_admin()
    )

@app.route('/superadmin/reports/download')
@role_required('superadmin')
def superadmin_reports_download():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID",
        "Plot Name",
        "Grade",
        "Maturity %",
        "Estimated TCH",
        "Estimated LKG/TC",
        "Created At"
    ])
    for scan in scans:
        tch, lkg_tc, _ = estimate_scan_metrics(scan)
        writer.writerow([
            scan.id,
            scan.plot_name,
            scan.grade,
            scan.maturity_pct,
            tch,
            lkg_tc,
            scan.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])

    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=superadmin_report.csv'
    return response

@app.route('/superadmin/audit')
@role_required('superadmin')
def superadmin_audit():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
    return render_template('superadmin_audit.html', logs=logs, current_admin=get_current_admin())

if __name__ == '__main__':
    app.run(debug=True)
