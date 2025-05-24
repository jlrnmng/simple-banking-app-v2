from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, RadioField, SelectField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, NumberRange, Optional, Regexp, Length
from models import User
from utils.sanitization import sanitize_username, sanitize_email, sanitize_account_number, sanitize_string
import re

# Form validation and sanitization to prevent injection and enforce strong passwords.

class StrongPassword(object):
    def __init__(self, message=None):
        if not message:
            message = 'Password must be at least 8 characters long, contain uppercase, lowercase, digit, and special character.'
        self.message = message

    def __call__(self, form, field):
        password = field.data
        # Enforce strong password policy to enhance security.
        if (len(password) < 8 or
            not re.search(r'[A-Z]', password) or
            not re.search(r'[a-z]', password) or
            not re.search(r'[0-9]', password) or
            not re.search(r'[\W_]', password)):
            raise ValidationError(self.message)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Regexp(r'^[A-Za-z0-9_]+$', message="Username must contain only letters, numbers, and underscores"),
        Length(min=3, max=25)
    ])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=128)])
    submit = SubmitField('Login')

    def validate(self, extra_validators=None):
        # Sanitize username before validation to prevent injection.
        if self.username.data:
            self.username.data = sanitize_username(self.username.data)
        return super(LoginForm, self).validate()

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Regexp(r'^[A-Za-z0-9_]+$', message="Username must contain only letters, numbers, and underscores"),
        Length(min=3, max=25)
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), StrongPassword()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        # Sanitize username before validation to prevent injection.
        if username.data:
            username.data = sanitize_username(username.data)
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        # Sanitize email before validation to prevent injection.
        if email.data:
            email.data = sanitize_email(email.data)
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

    def validate(self, extra_validators=None):
        return super(RegistrationForm, self).validate()

class TransferForm(FlaskForm):
    transfer_type = RadioField('Transfer Type', choices=[('username', 'Username'), ('account', 'Account Number')], default='username', validators=[DataRequired()])
    recipient_username = StringField('Recipient Username', validators=[Optional(), Regexp(r'^[A-Za-z0-9_]+$', message="Username must contain only letters, numbers, and underscores")])
    recipient_account = StringField('Recipient Account Number', validators=[Optional(), Regexp(r'^\d{10}$', message="Account number must be 10 digits")])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01, message="Amount must be positive")])
    submit = SubmitField('Transfer')

    def validate(self, extra_validators=None):
        rv = FlaskForm.validate(self, extra_validators=extra_validators)
        if not rv:
            return False

        if self.transfer_type.data == 'username' and not self.recipient_username.data:
            self.recipient_username.errors.append('Recipient username is required.')
            return False
        if self.transfer_type.data == 'account' and not self.recipient_account.data:
            self.recipient_account.errors.append('Recipient account number is required.')
            return False
        return True

from wtforms import BooleanField

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), StrongPassword()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class DepositForm(FlaskForm):
    account_number = StringField('Account Number', validators=[DataRequired(), Regexp(r'^\d{10}$', message="Account number must be 10 digits")])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01, message="Amount must be positive")])
    submit = SubmitField('Deposit')

class ConfirmTransferForm(FlaskForm):
    recipient_username = StringField('Recipient Username', validators=[DataRequired()])
    recipient_account = StringField('Recipient Account Number', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    transfer_type = HiddenField('Transfer Type', validators=[DataRequired()])
    submit = SubmitField('Confirm Transfer')

class UserEditForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    firstname = StringField('First Name', validators=[Optional(), Length(max=50)])
    lastname = StringField('Last Name', validators=[Optional(), Length(max=50)])
    address_line = StringField('Address Line', validators=[Optional(), Length(max=100)])
    postal_code = StringField('Postal Code', validators=[Optional(), Length(max=20)])
    phone = StringField('Phone Number', validators=[Optional(), Regexp(r'^\+?[0-9\s\-]+$', message="Invalid phone number")])
    region_code = SelectField('Region Code', choices=[], validators=[Optional()])
    region_name = SelectField('Region', choices=[], validators=[Optional()])
    province_code = SelectField('Province Code', choices=[], validators=[Optional()])
    province_name = SelectField('Province', choices=[], validators=[Optional()])
    city_code = SelectField('City Code', choices=[], validators=[Optional()])
    city_name = SelectField('City/Municipality', choices=[], validators=[Optional()])
    barangay_code = SelectField('Barangay Code', choices=[], validators=[Optional()])
    barangay_name = SelectField('Barangay', choices=[], validators=[Optional()])
    status = SelectField('Status', choices=[('pending', 'Pending'), ('active', 'Active'), ('deactivated', 'Deactivated')], validators=[Optional()])
    submit = SubmitField('Update')

class MFASetupForm(FlaskForm):
    token = StringField('Authentication Token', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Enable MFA')

class MFAVerifyForm(FlaskForm):
    token = StringField('Authentication Token', validators=[DataRequired(), Length(min=6, max=6)])
    remember_me = BooleanField('Remember this device')
    submit = SubmitField('Verify')
