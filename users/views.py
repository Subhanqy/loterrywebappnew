import logging  # This imports the logging module, which provides functions for logging messages and events.
from datetime import \
    datetime  # This imports the datetime class, which represents dates and times and provides methods for manipulating and formatting them

import \
    pyotp  # This imports the pyotp module, which provides functions for generating and verifying one-time passwords (OTPs).
from flask import Blueprint, render_template, flash, redirect, url_for, session, \
    request  # This imports several functions and classes from the flask module for creating views, rendering templates, displaying messages, redirecting users, and handling HTTP requests and sessions.
from flask_login import login_user, logout_user, current_user, \
    login_required  # This imports several functions from the flask_login module for handling user authentication and session management.
from werkzeug.security import check_password_hash

from app import \
    db, \
    requires_roles  # This imports the db object, which is probably an instance of a Flask extension for interacting with the database.
from models import User  # This imports the User class, which is probably a database model representing a user.
from users.forms import RegisterForm, \
    LoginForm  # this imports the RegisterForm and LoginForm classes, which are probably Flask forms for rendering and validating user registration and login forms.

# CONFIG
# Create a Flask blueprint for the users module
users_blueprint = Blueprint('users', __name__, template_folder='templates')

# View for user registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # Create a form object for user registration
    form = RegisterForm()

    # If the request method is POST or the form is valid
    if form.validate_on_submit():
        # Query the database for a user with the same email address as the form data
        user = User.query.filter_by(email=form.email.data).first()
        # If this returns a user, then the email already exists in the database

        # If the email already exists, redirect the user back to the signup page with an error message
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # Create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user')

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Notify the admin when someone has registered
        logging.warning('SECURITY - User registration [%s , %s]',
                        form.email.data, request.remote_addr)

        # Redirect the user to the login page
        return redirect(url_for('users.login'))
    # If the request method is GET or the form is not valid, re-render the signup page
    return render_template('users/register.html', form=form)


# View user login.
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    # If session attribute 'logins' does not exist, create a new one with a value of 0.
    if not session.get('logins'):
        session['logins'] = 0
    # If the number of login attempts is 3 or more, create an error message.
    elif session.get('logins') >= 3:
        flash('Number of incorrect logins exceeded.')

    form = LoginForm()

    # If the form has been filled out and submitted, validate it.
    if form.validate_on_submit():
        # Increase login attempts by 1.
        session['logins'] += 1

        # Check if the entered email is in the database.
        user = User.query.filter_by(email=form.email.data).first()

        # Check if the entered password matches the password stored in the database.
        if not user or not check_password_hash(user.password, form.password.data):
            # Update logs with an invalid login attempt.
            logging.warning('SECURITY - Invalid login attempt [%s, %s]', form.email.data, request.remote_addr)

            # If the email and password do not match, create an error message based on the number of login attempts.
            if session['logins'] == 3:
                flash('Number of incorrect logins exceeded.')
            elif session['logins'] == 2:
                flash('Please check your login details and try again. 1 login attempt remaining.')
            else:
                flash('Please check your login details and try again. 2 login attempts remaining.')

            # Redirect to the login page.
            return render_template('users/login.html', form=form)

        # If the entered PIN matches the user's PIN stored in the database,
        if pyotp.TOTP(user.pin_key).verify(form.pin.data):
            # reset login attempts to 0.
            session['logins'] = 0

            # Log the user in.
            login_user(user)

            # Update the user's last and current login times.
            user.last_logged_in = user.current_logged_in
            user.current_logged_in = datetime.now()
            db.session.commit()

            # Update logs with a successful login.
            logging.warning('SECURITY - Log in [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)

            # Redirect the user to the appropriate page based on their role.
            if current_user.role == 'admin':
                return redirect(url_for('admin.admin'))
            else:
                return redirect(url_for('users.profile'))

        # If the entered PIN does not match the user's stored PIN,
        else:
            # create an error message.
            flash("You have supplied an invalid 2FA token!", "danger")

    # If the form has not been submitted, or if it is invalid, render the login page.
    return render_template('users/login.html', form=form)
# Logs the user out
@users_blueprint.route('/logout')
@login_required
def logout():
    logging.warning('SECURITY - Log out [%s, %s]',
                    current_user.id,
                    current_user.email)
    logout_user()
    return redirect(url_for('index'))


# view user profile
@users_blueprint.route('/profile')
@login_required
@requires_roles('user')
def profile():
    return render_template('users/profile.html', firstname=current_user.firstname)


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)

# View admin, Notifies when admin has tried to be accessed
@users_blueprint.route('/admin')
@login_required
@requires_roles('admin')
def admin():
    logging.warning('SECURITY - User attempts Lottery [%s, %s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    current_user.role,
                    request.remote_addr)
    return render_template('admin/admin.html')

# View admin, Notifies when lottery has tried to be accessed
@users_blueprint.route('/lottery')
@login_required
@requires_roles('user')
def lottery():
    logging.warning('SECURITY - Lottery [%s, %s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    current_user.role,
                    request.remote_addr)
    return render_template('lottery/lottery.html')