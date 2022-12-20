# IMPORTS
import copy # used to make deep copies of objects
import logging # used for logging messages
import os # used to interact with the operating system
from functools import wraps # used to decorate functions

# dotenv is used to load environment variables from a .env file
# these variables can be used to store sensitive information such as passwords and keys
from dotenv import load_dotenv

# Flask is a web framework for Python
# render_template is used to render HTML templates with Jinja2
# request is used to access information about the current request
# abort is used to raise an HTTPException for a specific HTTP status code
from flask import Flask, render_template, request, abort

# LoginManager is used to handle user authentication in Flask
# current_user is a proxy for the current logged-in user
from flask_login import LoginManager, current_user

# SQLAlchemy is an ORM (Object-Relational Mapper) for Python
# It allows you to interact with databases using Python objects
from flask_sqlalchemy import SQLAlchemy

# Talisman is a Flask extension that helps secure your Flask app with various HTTP headers
# Content Security Policy (CSP) headers can be used to prevent cross-site scripting (XSS) attacks
from flask_talisman import Talisman

# Load environment variables from the .env file
load_dotenv()


# LOGGING
# This class is used to filter log messages based on their content
class SecurityFilter(logging.Filter):
    def filter(self, record):
        # Only log messages that contain the string "SECURITY"
        return "SECURITY" in record.getMessage()


# CONFIG
# Create an instance of the Flask class
app = Flask(__name__)

# Configure Flask app with various settings
# These settings are stored in a dictionary called app.config
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') # used to sign cookies and protect the app from tampering
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lottery.db' # the database URI
app.config['SQLALCHEMY_ECHO'] = os.getenv('SQLALCHEMY_ECHO') # echo SQLAlchemy log messages to the console
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') # track modifications to objects and emit signals
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY') # the public key for Google's reCAPTCHA service
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY') # the private key for Google's reCAPTCHA service


# FUNCTIONS
def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.roles not in roles:
                logging.warning('SECURITY - Unauthorised access attempt [%s, %s, %s, %s]',
                                current_user.id,
                                current_user.email,
                                current_user.role,
                                request.remote_addr)
                # Redirect the user to an unauthorised notice!
                return abort(403, 'Forbidden')
            return f(*args, **kwargs)

        return wrapped

    return wrapper


# decrypt original draws
def decrypt_draws(draws):
    # creates a list of copied draw objects which are independent of database.
    draws_copies = list(map(lambda x: copy.deepcopy(x), draws))
    # empty list for decrypted copied draw objects
    decrypted_draws = []

    # decrypt each copied draw object and add it to decrypted_draws array.
    for d in draws_copies:
        d.view_draw(current_user.draw_key)
        decrypted_draws.append(d)

    return decrypted_draws


# initialise database
db = SQLAlchemy(app)

# Security Headers
# Content Security Policy (CSP) headers used to prevent cross-site scripting (XSS) attacks
csp = {
    'default-src': ['\'self\'', 'https://cdnjs.cloudflare.com/ajax/libs/bulma/0.7.2/css/bulma.min.css'],
    'frame-src': ['\'self\'', 'https://www.google.com/recaptcha/', 'https://recaptcha.google.com/recaptcha/'],
    'script-src': ['\'self\'', '\'unsafe-inline\'', 'https://www.google.com/recaptcha/',
                   'https://www.gstatic.com/recaptcha/']
}

# Initialize Talisman with the Flask app and the CSP headers
talisman = Talisman(app, content_security_policy=csp)

# Set error handlers for various HTTP status codes
@app.errorhandler(400)
def handle_bad_request(error):
    # Render the 400.html template with a 400 Bad Request HTTP status code
    return render_template('errors/400.html'), 400

@app.errorhandler(400)
def handle_unauthorized(error):
    # Render the 401.html template with a 401 Unauthorized HTTP status code
    return render_template('errors/400.html'), 401

@app.errorhandler(403)
def handle_forbidden(error):
    # Render the 403.html template with a 403 Forbidden HTTP status code
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def handle_not_found(error):
    # Render the 404.html template with a 404 Not Found HTTP status code
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def handle_server_error(error):
    # Render the 500.html template with a 500 Internal Server Error HTTP status code
    return render_template('errors/500.html'), 500

# BLUEPRINTS
# import blueprints
from users.views import users_blueprint
from admin.views import admin_blueprint
from lottery.views import lottery_blueprint

# register blueprints with app
app.register_blueprint(users_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(lottery_blueprint)

# import User model
from models import User

# instance of Login manager
login_manager = LoginManager()

# Set the login view for the login manager
login_manager.login_view = 'users.login'

# Initialize the login manager with the Flask app
login_manager.init_app(app)

# Set the user loader function for the login manager
# This function is used to load a user given their unique identifier
@login_manager.user_loader
def load_user(id):
    # Return the user with the specified id
    return User.query.get(int(id))

# RUN
if __name__ == '__main__':
    # Run the app if the script is being run directly (e.
    app.run()
