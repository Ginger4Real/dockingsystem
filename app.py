from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from PIL import Image, ImageDraw, ImageFont
import io
import datetime
import pyotp
import qrcode
import base64
import os
import shutil
import argparse
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = '7f56c59c519e2f0c8b480c8a3a9b6310'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///docks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
TEMPLATE_IMAGE_PATH = 'static/licenseplate.png'
BACKUP_DIR = 'backup'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    two_fa_secret = db.Column(db.String(16), nullable=True)
    two_fa_enabled = db.Column(db.Boolean, default=False)

    def delete(self):
        if self.email == 'admin@admin.com':
            raise Exception("Cannot delete the admin user")
        db.session.delete(self)
        db.session.commit()

class Dock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.Integer, unique=True, nullable=False)
    assigned = db.Column(db.Boolean, default=False)
    license_plate = db.Column(db.String(20), nullable=True)

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dock_number = db.Column(db.Integer, nullable=False)
    license_plate = db.Column(db.String(20), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not User.query.get(session['user_id']).is_admin:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.cli.command('initdb')
def initdb():
    db.create_all()
    if not User.query.filter_by(email='admin@admin.com').first():
        admin_user = User(email='admin@admin.com', password=generate_password_hash('Dikketieten123'), is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
    print("Initialized the database and created the default admin user.")
    
@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        user.two_fa_enabled = True
        user.two_fa_secret = pyotp.random_base32()
        db.session.commit()
        flash('2FA has been enabled. Please scan the QR code with your authenticator app.', 'success')
        return redirect(url_for('setup_2fa'))

    totp = pyotp.TOTP(user.two_fa_secret)
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(totp.provisioning_uri(name=user.email, issuer_name='Docking System'))
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()

    return render_template('setup_2fa.html', qr_code=img_str)

@app.route('/manage-users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        user = User.query.get(user_id)
        if user:
            if user.email == 'admin@admin.com':
                flash('Cannot modify the default admin user.', 'error')
            else:
                if action == 'make_admin':
                    user.is_admin = True
                elif action == 'remove_admin':
                    user.is_admin = False
                elif action == 'delete':
                    try:
                        user.delete()
                    except Exception as e:
                        flash(str(e), 'error')
                        return redirect(url_for('manage_users'))
                db.session.commit()
                flash('User updated successfully', 'success')
        return redirect(url_for('manage_users'))

    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin_panel', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_panel():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        user = User.query.get(user_id)
        if user.email == 'admin@admin.com':
            flash('Cannot modify the default admin user.', 'error')
        else:
            if action == 'make_admin':
                user.is_admin = True
            elif action == 'remove_admin':
                user.is_admin = False
            elif action == 'disable_2fa':
                user.two_fa_enabled = False
                user.two_fa_secret = None
            elif action == 'delete':
                try:
                    user.delete()
                    flash('User deleted successfully.', 'success')
                except Exception as e:
                    flash(str(e), 'danger')
            db.session.commit()
            flash('Action completed successfully.', 'success')
        return redirect(url_for('admin_panel'))
    users = User.query.all()
    return render_template('admin_panel.html', users=users)

@app.route('/backup_restore', methods=['POST'])
@login_required
@admin_required
def backup_restore():
    action = request.form.get('action')
    if action == 'backup':
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        backup_file = f"{BACKUP_DIR}/backup_{timestamp}.db"
        shutil.copy('docks.db', backup_file)
        flash('Database backup created successfully.', 'success')
        return redirect(url_for('admin_panel'))
    elif action == 'restore':
        backups = sorted(os.listdir(BACKUP_DIR), reverse=True)
        if backups:
            latest_backup = backups[0]
            latest_backup_path = os.path.join(BACKUP_DIR, latest_backup)
            shutil.copy(latest_backup_path, 'docks.db')
            flash('Database restored from latest backup.', 'success')
        else:
            flash('No backup files found.', 'danger')
        return redirect(url_for('admin_panel'))
    return redirect(url_for('admin_panel'))

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        if otp_code:
            user = db.session.get(User, session.get('user_id'))
            if user and pyotp.TOTP(user.two_fa_secret).verify(otp_code):
                session['authenticated'] = True
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid 2FA code', 'danger')
        else:
            flash('OTP code is required', 'danger')
        return redirect(url_for('verify_2fa'))

    return render_template('verify_2fa.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if user.two_fa_enabled:
                session['user_id'] = user.id
                session['is_admin'] = user.is_admin
                return redirect(url_for('verify_2fa'))
            
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            session['authenticated'] = True
            return redirect(url_for('index'))
        
        flash('Invalid login credentials', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if new_password:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password updated successfully', 'success')
            return redirect(url_for('settings'))
        
        if 'enable_2fa' in request.form:
            return redirect(url_for('setup_2fa'))
        
        if 'disable_2fa' in request.form:
            user.two_fa_enabled = False
            user.two_fa_secret = None
            db.session.commit()
            flash('2FA disabled successfully', 'success')
            return redirect(url_for('settings'))

    return render_template('settings.html', user=user)

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    new_password = request.form.get('new_password')
    user = db.session.get(User, session['user_id'])
    if new_password and user:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password updated successfully', 'success')
    else:
        flash('Password update failed', 'error')
    return redirect(url_for('settings'))

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    session.pop('authenticated', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    user_id = session.get('user_id')
    is_admin = session.get('is_admin')
    return render_template('index.html', user_id=user_id, is_admin=is_admin)

@app.route('/dock-status')
@login_required
def dock_status():
    return render_template('dock_status.html')

@app.route('/docks')
@login_required
def get_docks():
    docks = Dock.query.all()
    dock_assignments = {dock.number: {'license_plate': None, 'timestamp': None} for dock in docks}
    
    assignments = Assignment.query.all()
    for assignment in assignments:
        dock_number = assignment.dock_number
        if (dock_assignments[dock_number]['timestamp'] is None or 
            assignment.timestamp > dock_assignments[dock_number]['timestamp']):
            dock_assignments[dock_number] = {
                'license_plate': assignment.license_plate,
                'timestamp': assignment.timestamp
            }
    
    return jsonify({'docks': [{'number': number, **details} for number, details in dock_assignments.items()]})

@app.route('/assign-dock', methods=['POST'])
@login_required
def assign_dock():
    data = request.json
    license_plate = data.get('license_plate')
    dock_number = int(data.get('dock_number'))
    
    dock = Dock.query.filter_by(number=dock_number).first()
    if dock:
        if not dock.assigned:
            dock.assigned = True
            dock.license_plate = license_plate
            db.session.add(Assignment(dock_number=dock.number, license_plate=license_plate))
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Dock is already occupied'})
    return jsonify({'success': False, 'message': 'Invalid dock number'})

@app.route('/clear-dock', methods=['POST'])
@login_required
def clear_dock():
    data = request.json
    dock_number = int(data.get('dock_number'))
    
    dock = Dock.query.filter_by(number=dock_number).first()
    if dock:
        if dock.assigned:
            dock.assigned = False
            dock.license_plate = None
            db.session.add(Assignment(dock_number=dock.number, license_plate=None))
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Dock is already empty'})
    return jsonify({'success': False, 'message': 'Invalid dock number'})

@app.route('/license-plate-image/<license_plate>')
@login_required
def license_plate_image(license_plate):
    with Image.open(TEMPLATE_IMAGE_PATH) as img:
        draw = ImageDraw.Draw(img)
        try:
            font = ImageFont.truetype('arial.ttf', size=40)
        except IOError:
            font = ImageFont.load_default()
        
        text_position = (135, 40)
        text_color = (0, 0, 0)
        
        draw.text(text_position, license_plate, font=font, fill=text_color)
        
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr.seek(0)
        
        return send_file(img_byte_arr, mimetype='image/png')

@app.route('/users')
@admin_required
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run a Flask server.")
    parser.add_argument('--host', default='0.0.0.0', help='Host IP address to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port number to bind to')
    args = parser.parse_args()

    app.run(host=args.host, port=args.port, debug=True)
