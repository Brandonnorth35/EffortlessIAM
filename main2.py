from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import pyotp
import time
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_accounts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
db = SQLAlchemy(app)
bcrypt = Bcrypt()

# Set up logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    phone_number = db.Column(db.String(20))
    password_hash = db.Column(db.String(128), nullable=False)
    secrets = db.relationship('Secret', backref='user', lazy=True)

    def add_totp_secret(self, name, secret_value):
        try:
            # Validate input
            if not name or not secret_value:
                raise ValueError("Name and secret_value must be provided")

            new_secret = Secret(user_id=self.id, name=name, secret=secret_value)
            db.session.add(new_secret)
            db.session.commit()
            return new_secret
        except Exception as e:
            logging.error(f"Error adding TOTP secret for user {self.id}: {e}")
            raise e

    def generate_totp(self, secret):
        try:
            # Validate input
            if not secret:
                raise ValueError("Secret must be provided")

            totp = pyotp.TOTP(secret)
            current_time = int(time.time())
            remaining_seconds = 30 - (current_time % 30)
            token = totp.now()
            return token, remaining_seconds
        except Exception as e:
            logging.error(f"Error generating TOTP for user {self.id}: {e}")
            raise e

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(128))
    secret = db.Column(db.String(128), nullable=False)

    def __init__(self, user_id, name, secret):
        self.user_id = user_id
        self.name = name
        self.secret = secret

    def add_totp_secret(self, name, secret_value):
        try:
            # Validate input
            if not name or not secret_value:
                raise ValueError("Name and secret_value must be provided")

            new_secret = Secret(user_id=self.id, name=name, secret=secret_value)
            db.session.add(new_secret)
            db.session.commit()
            return new_secret
        except Exception as e:
            logging.error(f"Error adding TOTP secret for user {self.user_id}: {e}")
            raise e

@app.route('/')
def homepage():
    return redirect('/login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']
            phone_number = request.form['phone_number']

            # Validate input
            if not email or not password:
                raise ValueError("Email and password are required")

            # Hash the password using Bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Create a new user instance and add to the database
            new_user = User(email=email, password_hash=hashed_password, phone_number=phone_number)
            db.session.add(new_user)
            db.session.commit()

            # Set user_id in session after successful signup
            session['user_id'] = new_user.id
            return redirect('/dashboard')
        except Exception as e:
            logging.error(f"Error in signup: {e}")
            return render_template('signup.html', error_message='Error signing up')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']

            # Validate input
            if not email or not password:
                raise ValueError("Email and password are required")

            # Query user by email
            user = User.query.filter_by(email=email).first()

            # Validate user and password using Bcrypt
            if user and bcrypt.check_password_hash(user.password_hash, password):
                # Set user_id in session after successful login
                session['user_id'] = user.id
                return redirect('/dashboard')
            else:
                return render_template('login.html', error_message='Invalid email or password')
        except Exception as e:
            logging.error(f"Error in login: {e}")
            return render_template('login.html', error_message='Error logging in')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/login')

    try:
        # Query user and generate TOTP tokens for user's secrets
        user = User.query.get(user_id)
        totp_tokens = []
        for secret in user.secrets:
            token, remaining_seconds = user.generate_totp(secret.secret)
            totp_tokens.append({'name': secret.name, 'token': token, 'remaining_seconds': remaining_seconds})

        return render_template('dashboard.html', user=user, totp_tokens=totp_tokens)
    except Exception as e:
        logging.error(f"Error in dashboard: {e}")
        return render_template('dashboard.html', error_message='Error loading dashboard')

@app.route('/add_account', methods=['GET', 'POST'])
def add_account():
    if request.method == 'POST':
        try:
            user_id = session.get('user_id')
            if not user_id:
                return redirect('/login')

            user = User.query.get(user_id)
            if not user:
                return redirect('/login')

            name = request.form.get('account_name')
            secret_with_spaces = request.form.get('totp_secret', '')
            secret = secret_with_spaces.replace(' ', '')

            # Validate input
            if not name or not secret:
                raise ValueError("Name and secret are required")

            # Add new TOTP secret for the user
            user.add_totp_secret(name=name, secret_value=secret)
            return redirect('/dashboard')
        except Exception as e:
            logging.error(f"Error in adding account: {e}")
            return render_template('add_account.html', error_message='Error adding account')

    elif request.method == 'GET':
        return render_template('add_account.html')
    
    return "Method Not Allowed", 405

# Create database tables based on defined models
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
