from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from flask_mail import Mail, Message
import pyotp
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hospital.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'simonmagwe081@gmail.com'
app.config['MAIL_PASSWORD'] = 'oynz udmp kyfy ltyg'
mail = Mail(app)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    doctor_username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')


# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('patient', 'Patient')],
                       validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired()])
    submit = SubmitField('Verify')


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)


def send_otp(email):
    totp = pyotp.TOTP('base32secret3232')
    otp = totp.now()
    msg = Message('Your OTP Code', sender='simonmagwe081@gmail.com', recipients=[email])
    msg.body = f'Your OTP code is {otp}. Valid for 10 minutes.'
    mail.send(msg)
    return otp


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists!')
            return redirect(url_for('register'))

        new_user = User(
            username=form.username.data,
            password=hash_password(form.password.data),
            role=form.role.data,
            email=form.email.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password(form.password.data, user.password):
            session['username'] = user.username
            otp = send_otp(user.email)
            session['otp'] = otp
            return redirect(url_for('verify_otp'))
        flash('Invalid credentials!')
    return render_template('login.html', form=form)


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()
    if form.validate_on_submit():
        if form.otp.data == session.get('otp'):
            session['authenticated'] = True
            user = User.query.filter_by(username=session['username']).first()
            return redirect(url_for(f'{user.role}_dashboard'))
        flash('Invalid OTP!')
    return render_template('verify_otp.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# Dashboard Routes
@app.route('/patient_dashboard')
def patient_dashboard():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'patient':
        return redirect(url_for('login'))
    user_appointments = Appointment.query.filter_by(patient_username=session['username']).all()
    return render_template('patient_dashboard.html', appointments=user_appointments)


@app.route('/doctor_dashboard')
def doctor_dashboard():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'doctor':
        return redirect(url_for('login'))
    doctor_appointments = Appointment.query.filter_by(doctor_username=session['username']).all()
    return render_template('doctor_dashboard.html', appointments=doctor_appointments)


@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'admin':
        return redirect(url_for('login'))
    users_list = User.query.all()
    return render_template('admin_dashboard.html', users=users_list)


@app.route('/add_user', methods=['POST'])
def add_user():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'admin':
        return redirect(url_for('login'))

    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    email = request.form['email']

    if User.query.filter_by(username=username).first():
        flash('Username already exists!')
        return redirect(url_for('admin_dashboard'))

    if role not in ['doctor', 'insurer', 'admin', 'patient']:
        flash('Invalid role!')
        return redirect(url_for('admin_dashboard'))

    new_user = User(
        username=username,
        password=hash_password(password),
        role=role,
        email=email
    )
    db.session.add(new_user)
    db.session.commit()
    flash(f'{role.capitalize()} {username} added successfully!')
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_user', methods=['POST'])
def delete_user():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'admin':
        return redirect(url_for('login'))

    username = request.form['username']
    user = User.query.filter_by(username=username).first()
    if user and user.role in ['doctor', 'insurer']:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {username} deleted successfully!')
    else:
        flash('User not found or cannot be deleted!')
    return redirect(url_for('admin_dashboard'))


@app.route('/insurer_dashboard')
def insurer_dashboard():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'insurer':
        return redirect(url_for('login'))
    all_appointments = Appointment.query.all()
    return render_template('insurer_dashboard.html', appointments=all_appointments)


# Appointment Handling
@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'patient':
        return redirect(url_for('login'))
    doctor = request.form['doctor']
    date = request.form['date']
    new_appointment = Appointment(
        patient_username=session['username'],
        doctor_username=doctor,
        date=date,
        status='pending'
    )
    db.session.add(new_appointment)
    db.session.commit()
    return redirect(url_for('patient_dashboard'))


@app.route('/update_appointment', methods=['POST'])
def update_appointment():
    if not session.get('authenticated') or User.query.filter_by(username=session['username']).first().role != 'doctor':
        return redirect(url_for('login'))
    apt_id = request.form['apt_id']
    status = request.form['status']
    appointment = Appointment.query.get(apt_id)
    if appointment:
        appointment.status = status
        db.session.commit()
    return redirect(url_for('doctor_dashboard'))




# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)