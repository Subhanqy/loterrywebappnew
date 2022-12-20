# This code defines a Flask web application that implements a lottery system.
# It defines two main classes: User and Draw, which are used to store information about users and lottery draws, respectively.
# The User class has fields for storing authentication information, activity information, and personal information about the user.# The Draw class has fields for storing the ID of the user who submitted the draw, the numbers that were submitted,
# whether the draw has already been played, whether the draw matches the master draw, and the lottery round that the draw is for.
# The init_db function is used to initialize the database by creating the necessary tables.
from datetime import datetime

import bcrypt # provides hashing and salting functions for storing passwords securely
import pyotp # generates and verifies one-time passwords
from flask_login import UserMixin # provides user session management for Flask applications
from app import db, app # imports the Flask application instance and the database instance from the app package
from cryptography.fernet import Fernet # provides a high level interface for symmetric encryption using the AES cipher

# Encrypts data using the provided key
def encrypt(data, draw_key):
    return Fernet(draw_key).encrypt(bytes(data, 'utf-8'))

# Decrypts data using the provided key
def decrypt(data, draw_key):
    return Fernet(draw_key).decrypt(bytes(data)).decode('utf-8')

#
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    pin_key = db.Column(db.String(100), nullable=False)

    # User activity information
    registered_on = db.Column(db.DateTime, nullable=True)
    last_logged_in = db.Column(db.DateTime, nullable=True)
    current_logged_in = db.Column(db.DateTime, nullable=True)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False, default='user')
    draw_key = db.Column(db.String(100), nullable=False)

    # Define the relationship to Draw
    draws = db.relationship('Draw')
    def __init__(self, email, firstname, lastname, phone, password, role):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.pin_key = pyotp.random_base32()
        self.role = role
        self.registered_on = datetime.now()
        self.last_logged_in = None
        self.current_logged_in = None

# Draw method for the lottery system
class Draw(db.Model):
    __tablename__ = 'draws'

    id = db.Column(db.Integer, primary_key=True)

    # ID of user who submitted draw
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

    # 6 draw numbers submitted
    numbers = db.Column(db.String(100), nullable=False)

    # Draw has already been played (can only play draw once)
    been_played = db.Column(db.BOOLEAN, nullable=False, default=False)

    # Draw matches with master draw created by admin (True = draw is a winner)
    matches_master = db.Column(db.BOOLEAN, nullable=False, default=False)

    # True = draw is master draw created by admin. User draws are matched to master draw
    master_draw = db.Column(db.BOOLEAN, nullable=False)

    # Lottery round that draw is used
    lottery_round = db.Column(db.Integer, nullable=False, default=0)
    # This class represents a lottery ticket.
    def __init__(self, user_id, numbers, master_draw, lottery_round):
        self.user_id = user_id
        self.numbers = numbers
        self.been_played = False
        self.matches_master = False
        self.master_draw = master_draw
        self.lottery_round = lottery_round

    # Encrypt a string using the Fernet algorithm
    def encrypt(self, key):
        # Encrypt the string and return the encrypted message
        return Fernet(key).encrypt(bytes(self, 'utf-8'))

    # Decrypt a string using the Fernet algorithm
    def decrypt(self, key):
        # Decrypt the string and return the decrypted message
        return Fernet(key).decrypt(bytes(self, 'utf-8'))

# This function initializes the database and creates an admin user
def init_db():
    with app.app_context():
        # Drop all existing tables in the database
        db.drop_all()
        # Create all tables in the database
        db.create_all()
        # Create a new user with the admin role
        admin = User(email='admin@email.com',
                     password='Admin1!',
                     firstname='Alice',
                     lastname='Jones',
                     phone='0191-123-4567',
                     role='admin')
        # Add the admin user to the database session
        db.session.add(admin)
        # Commit the changes to the database
        db.session.commit()

