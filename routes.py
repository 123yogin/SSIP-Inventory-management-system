from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from models import User
from forms import RegistrationForm, LoginForm
from forms import ForgotPasswordForm



@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        # Add your logic to handle the forgot password request here
        # For example, send a password reset email to the user
        flash('A password reset link has been sent to your email address.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form)

@app.route('/')
@app.route('/index')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash('Login successful!', 'success')
            flash('Invalid credentials', 'error')
            return redirect(url_for('register'))
        
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))