from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, validators


class RegisterForm(FlaskForm):
    email = StringField('Email',
                        [validators.DataRequired(), validators.Email(message="Please enter a valid email address.")])
    firstname = StringField('First Name', [validators.DataRequired(message="Please enter your first name."),
                                           validators.Regexp(r'^[^*?!\'^+%&/()=}\]\[{$#@<>-]*$',
                                                             message="Please enter a valid first name.")])
    lastname = StringField('Last Name', [validators.DataRequired(message="Please enter your last name."),
                                         validators.Regexp(r'^[^*?!\'^+%&/()=}\]\[{$#@<>-]*$',
                                                           message="Please enter a valid last name.")])
    phone = StringField('Phone', [validators.DataRequired(message="Please enter your phone number."),
                                  validators.Regexp(r'^\d{4}-\d{3}-\d{4}$',
                                                    message="Please enter a valid phone number.")])
    password = PasswordField('Password', [validators.DataRequired(message="Please enter a password."),
                                          validators.Length(min=6, max=12,
                                                            message="Please enter a password between 6 and 12 characters long."),
                                          validators.Regexp(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^\w\d\s]).{6,12}$',
                                                            message="Please enter a password with at least one uppercase letter, one lowercase letter, one number, and one special character.")])
    confirm_password = PasswordField('Confirm Password',
                                     [validators.DataRequired(message="Please confirm your password."),
                                      validators.EqualTo('password', message="Passwords do not match")])
    pin = StringField('Pin',
                      [validators.DataRequired(message='Pin must be 32 characters long.')])
    submit = SubmitField()


# LoginForm is a form for logging in a user.
class LoginForm(FlaskForm):
    # email is a StringField that is required.
    email = StringField('Email', [validators.DataRequired(message="Please enter your username.")])
    # password is a PasswordField that is required.
    password = PasswordField('Password', [validators.DataRequired(message="Please enter your password.")])
    # pin is a StringField that is not required.
    pin = StringField()
    # recaptcha is a RecaptchaField provided by the Flask-WTF extension.
    recaptcha = RecaptchaField()
    # submit is a SubmitField that allows the user to submit the form.
    submit = SubmitField()
