from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import bcrypt
import pyotp
import os
import socket

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ssbhospital.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'simonmagwe081@gmail.com'  # email
app.config['MAIL_PASSWORD'] = 'oynz udmp kyfy ltyg'     # app-specific password
app.config['MAIL_DEBUG'] = True
mail = Mail(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'doctor', 'patient', 'insurer', 'supplier'
    email = db.Column(db.String(120), unique=True, nullable=False)
    approved = db.Column(db.Boolean, default=False)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    doctor_username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending')
    insurance_status = db.Column(db.String(20), nullable=True, default='Pending')

class SupplyOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    supplier_username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    item = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    order_date = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending')

class Availability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    slots = db.Column(db.Integer, nullable=False)

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[
        ('patient', 'Patient'), ('doctor', 'Doctor')], validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired()])
    submit = SubmitField('Verify')

class OrderForm(FlaskForm):
    supplier_username = StringField('Supplier Username', validators=[DataRequired()])
    item = StringField('Item', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    order_date = StringField('Order Date (YYYY-MM-DD)', validators=[DataRequired()])
    submit = SubmitField('Place Order')

# Utility Functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def send_otp(email):
    totp = pyotp.TOTP('base32secret3232')  # Use a unique secret 
    otp = totp.now()
    msg = Message('Your OTP Code - SSB Hospital', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your OTP code is {otp}. Valid for 10 minutes.'
    try:
        print(f"Sending OTP to {email}")
        mail.send(msg)
        print("OTP sent successfully")
        return otp
    except socket.timeout:
        raise Exception("Connection timed out while sending OTP.")
    except Exception as e:
        raise Exception(f"Failed to send OTP: {str(e)}")

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists!', 'error')
        elif User.query.filter_by(email=form.email.data).first():
            flash('Email already in use!', 'error')
        else:
            approved = form.role.data == 'patient'  # Auto-approve patients
            new_user = User(
                username=form.username.data,
                password=hash_password(form.password.data),
                role=form.role.data,
                email=form.email.data,
                approved=approved
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Await admin approval if required.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password(form.password.data, user.password) and user.approved:
            session['pending_username'] = user.username
            try:
                otp = send_otp(user.email)
                session['otp'] = otp
                return render_template('verify_otp.html', form=OTPForm())
            except Exception as e:
                flash(str(e), 'error')
        else:
            flash('Invalid credentials or account not approved!', 'error')
    return render_template('login.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()
    if form.validate_on_submit():
        if form.otp.data == session.get('otp'):
            username = session.pop('pending_username', None)
            session.pop('otp', None)
            session['authenticated'] = True
            session['username'] = username
            user = User.query.filter_by(username=username).first()
            return redirect(url_for(f'{user.role}_dashboard'))
        flash('Invalid OTP!', 'error')
    return render_template('verify_otp.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Dashboard Routes
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'admin':
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    users = User.query.all()
    suppliers = User.query.filter_by(role='supplier').all()
    orders = SupplyOrder.query.all()
    form = OrderForm()
    return render_template('admin_dashboard.html', user=user, users=users, suppliers=suppliers, orders=orders, form=form)

@app.route('/add_user', methods=['POST'])
def add_user():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'admin':
        return redirect(url_for('login'))
    username = request.form['username']
    password = hash_password(request.form['password'])
    role = request.form['role']
    email = request.form['email']
    if User.query.filter_by(username=username).first():
        flash('Username already exists!', 'error')
    else:
        new_user = User(username=username, password=password, role=role, email=email, approved=True)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/approve_user', methods=['POST'])
def approve_user():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'admin':
        return redirect(url_for('login'))
    username = request.form['username']
    user = User.query.filter_by(username=username).first()
    if user:
        user.approved = True
        db.session.commit()
        flash('User approved successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'admin':
        return redirect(url_for('login'))
    username = request.form['username']
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/place_order', methods=['POST'])
def place_order():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'admin':
        return redirect(url_for('login'))
    form = OrderForm()
    if form.validate_on_submit():
        new_order = SupplyOrder(
            supplier_username=form.supplier_username.data,
            item=form.item.data,
            quantity=form.quantity.data,
            order_date=form.order_date.data,
            status='Pending'
        )
        db.session.add(new_order)
        db.session.commit()
        flash('Order placed successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/doctor_dashboard', methods=['GET', 'POST'])
def doctor_dashboard():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'doctor':
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    appointments = Appointment.query.filter_by(doctor_username=user.username).all()
    availability = Availability.query.filter_by(doctor_username=user.username).all()
    return render_template('doctor_dashboard.html', user=user, appointments=appointments, availability=availability)
@app.route('/set_availability', methods=['POST'])
def set_availability():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'doctor':
        return redirect(url_for('login'))
    date = request.form['date']
    slots = request.form['slots']
    doctor_username = session['username']
    # Check if availability already exists for this date
    existing = Availability.query.filter_by(doctor_username=doctor_username, date=date).first()
    if existing:
        existing.slots = slots
        flash(f'Updated availability for {date} to {slots} slots!', 'success')
    else:
        new_availability = Availability(doctor_username=doctor_username, date=date, slots=slots)
        db.session.add(new_availability)
        flash(f'Availability set for {date} with {slots} slots successfully!', 'success')
    db.session.commit()
    return redirect(url_for('doctor_dashboard'))

@app.route('/patient_dashboard', methods=['GET', 'POST'])
def patient_dashboard():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'patient':
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    appointments = Appointment.query.filter_by(patient_username=user.username).all()
    return render_template('patient_dashboard.html', user=user, appointments=appointments)

@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'patient':
        return redirect(url_for('login'))
    doctor = request.form['doctor']
    date = request.form['date']
    if User.query.filter_by(username=doctor, role='doctor').first():
        new_appointment = Appointment(patient_username=session['username'], doctor_username=doctor, date=date, status='Pending')
        db.session.add(new_appointment)
        db.session.commit()
        flash('Appointment booked successfully!', 'success')
    else:
        flash('Invalid doctor username!', 'error')
    return redirect(url_for('patient_dashboard'))

@app.route('/insurer_dashboard', methods=['GET', 'POST'])
def insurer_dashboard():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'insurer':
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    appointments = Appointment.query.all()
    return render_template('insurer_dashboard.html', user=user, appointments=appointments)

@app.route('/supplier_dashboard', methods=['GET', 'POST'])
def supplier_dashboard():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'supplier':
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    orders = SupplyOrder.query.filter_by(supplier_username=user.username).all()
    return render_template('supplier_dashboard.html', user=user, orders=orders)

@app.route('/update_order', methods=['POST'])
def update_order():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'supplier':
        return redirect(url_for('login'))
    order_id = request.form['order_id']
    status = request.form['status']
    order = SupplyOrder.query.get_or_404(order_id)
    if order.supplier_username == session['username']:
        order.status = status
        db.session.commit()
        flash('Order status updated successfully!', 'success')
    else:
        flash('You can only update your own orders!', 'error')
    return redirect(url_for('supplier_dashboard'))

# Initialize Database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)