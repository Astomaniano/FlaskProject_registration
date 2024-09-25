from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
from forms import LoginForm, RegistrationForm, UpdateAccountForm
from models import User, db
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_pyfile('config.py')

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def home():
    return render_template('home.html', name=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Проверяем, существует ли уже пользователь с таким именем пользователя
        existing_user_by_username = User.query.filter_by(username=form.username.data).first()
        # Проверяем, существует ли уже пользователь с такой электронной почтой
        existing_user_by_email = User.query.filter_by(email=form.email.data).first()

        if existing_user_by_username:
            flash('Username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        if existing_user_by_email:
            flash('Email is already registered. Please use a different one.', 'danger')
            return redirect(url_for('register'))

        # Создаем нового пользователя
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.email.data != current_user.email:
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                flash('Email is already taken. Please use a different one.', 'danger')
                return redirect(url_for('account'))

        current_user.username = form.username.data
        current_user.email = form.email.data

        if form.password.data:
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            current_user.password = hashed_password

        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    return render_template('account.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
