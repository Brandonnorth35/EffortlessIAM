from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import pyotp
import time

# Initialize Flask application
app = Flask(__name__)

# Configure database URI and disable track modifications
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_accounts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set secret key for session management
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Initialize SQLAlchemy for database operations
db = SQLAlchemy(app)

# Initialize Bcrypt for password hashing
bcrypt = Bcrypt()

# Define User model for storing user information
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    phone_number = db.Column(db.String(20))
    password_hash = db.Column(db.String(128), nullable=False)
    secrets = db.relationship('Secret', backref='user', lazy=True)

    # Method to add a new TOTP secret for the user
    def add_totp_secret(self, name, secret_value):
        new_secret = Secret(user_id=self.id, name=name, secret=secret_value)
        db.session.add(new_secret)
        db.session.commit()
        return new_secret

    # Method to generate a TOTP token for a given secret
    def generate_totp(self, secret):
        totp = pyotp.TOTP(secret)
        current_time = int(time.time())
        remaining_seconds = 30 - (current_time % 30)
        token = totp.now()
        return token, remaining_seconds

# Define Secret model for storing user's TOTP secrets
class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(128))  # Name of the authentication method
    secret = db.Column(db.String(128), nullable=False)

    # Constructor to initialize a new TOTP secret
    def __init__(self, user_id, name, secret):
        self.user_id = user_id
        self.name = name
        self.secret = secret

    # Method to add a new TOTP secret for the user
    def add_totp_secret(self, name, secret_value):
        new_secret = Secret(user_id=self.id, name=name, secret=secret_value)
        db.session.add(new_secret)
        db.session.commit()
        return new_secret

# Define route for the homepage (redirect to login)
@app.route('/')
def homepage():
    return redirect('/login')

# Define route for user signup (GET: display signup form, POST: process signup)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        phone_number = request.form['phone_number']

        # Hash the password using Bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new user instance and add to the database
        new_user = User(email=email, password_hash=hashed_password, phone_number=phone_number)
        db.session.add(new_user)
        db.session.commit()

        # Set user_id in session after successful signup
        session['user_id'] = new_user.id
        return redirect('/dashboard')

    return render_template('signup.html')

# Define route for user login (GET: display login form, POST: process login)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Query user by email
        user = User.query.filter_by(email=email).first()

        # Validate password using Bcrypt
        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Set user_id in session after successful login
            session['user_id'] = user.id
            return redirect('/dashboard')
        else:
            return "Invalid email or password"

    return render_template('login.html')

# Define route for user dashboard (display user's TOTP tokens)
@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/login')

    # Query user and generate TOTP tokens for user's secrets
    user = User.query.get(user_id)
    totp_tokens = []
    for secret in user.secrets:
        token, remaining_seconds = user.generate_totp(secret.secret)
        totp_tokens.append({'name': secret.name, 'token': token, 'remaining_seconds': remaining_seconds})

    return render_template('dashboard.html', user=user, totp_tokens=totp_tokens)

# Define route for adding a new TOTP secret (GET: display form, POST: process form)
@app.route('/add_account', methods=['GET', 'POST'])
def add_account():
    if request.method == 'POST':
        user_id = session.get('user_id')
        if not user_id:
            return redirect('/login')

        user = User.query.get(user_id)
        if not user:
            return redirect('/login')

        name = request.form.get('account_name')
        secret_with_spaces = request.form.get('totp_secret', '')
        secret = secret_with_spaces.replace(' ', '')

        if name and secret:
            # Add new TOTP secret for the user
            user.add_totp_secret(name=name, secret_value=secret)
            return redirect('/dashboard')
        else:
            # Render add_account.html with error message for invalid form data
            return render_template('add_account.html', error_message='Invalid form data')

    elif request.method == 'GET':
        # Render add_account.html to display form for adding a new TOTP secret
        return render_template('add_account.html')
    
    # Handle other HTTP methods with a 405 Method Not Allowed response
    return "Method Not Allowed", 405

# Create database tables based on defined models
with app.app_context():
    db.create_all()

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
