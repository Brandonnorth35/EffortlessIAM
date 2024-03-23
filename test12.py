import logging
from flask import Flask, request, session, redirect, url_for, flash, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import hashlib
import os


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Suppress SQLALCHEMY_TRACK_MODIFICATIONS warning
import warnings
from sqlalchemy.exc import SAWarning
warnings.simplefilter("ignore", category=SAWarning)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_accounts.db'

db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_hash = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    password_vault = db.Column(db.JSON)

# Placeholder for storing user SSO information
user_sso_info = {}

# Route for signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if password and confirm password match
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        # Check if email is already registered
        existing_user = User.query.filter_by(email_hash=hashlib.sha256(email.encode()).hexdigest()).first()
        if existing_user:
            flash('Email already exists. Please login.', 'error')
            return redirect(url_for('login'))

        # Create new user
        new_user = User(email_hash=hashlib.sha256(email.encode()).hexdigest(), password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

# Function to generate a secure token
def generate_token(data):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(data)

# Before each request, initialize the list of apps in the session
@app.before_request
def before_request():
    if 'apps' not in session:
        session['apps'] = []

# Route to serve the homepage
@app.route('/')
def home():
    if 'username' in session:
        return render_template('homepage.html', username=session['username'])
    else:
        return redirect(url_for('login'))

# Route to login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if user is already logged in
    if 'username' in session:
        # Redirect logged-in user to the homepage
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if email is registered
        user = User.query.filter_by(email_hash=hashlib.sha256(email.encode()).hexdigest()).first()
        if user:
            # Check if credentials are valid
            if check_password_hash(user.password_hash, password):
                # Set up session to keep the user logged in
                session['username'] = email
                session['token'] = generate_token({'email': email})
                # Store user SSO information
                user_sso_info[email] = {'username': email, 'token': session['token']}
                # Redirect to the homepage
                return redirect('/')
            else:
                # If credentials are invalid, render login page with error message
                flash('Invalid email or password', 'error')
                return render_template('login.html')
        else:
            # If email is not registered, return message to register
            flash('Email not found. Please sign up.', 'error')
            return redirect(url_for('signup'))

    # If request method is GET, render the login page
    return render_template('login.html')

# Route to logout
@app.route('/logout')
def logout():
    # Check if user is logged in
    if 'username' in session:
        # Remove user SSO info
        del user_sso_info[session['username']]
        # Clear session variables
        session.clear()
        flash('You have been logged out successfully', 'success')
    return redirect('/login')

# Route to serve the SSO page
@app.route('/sso')
def sso():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Render the SSO page
    return render_template('sso.html', username=session['username'], apps=session['apps'])

# Route to add a new app to the SSO page
@app.route('/add_app', methods=['POST'])
def add_app():
    if 'username' not in session:
        return redirect(url_for('login'))

    app_name = request.form.get('app_name')
    app_url = request.form.get('app_url')

    if not app_name or not app_url:
        flash('Please provide both app name and URL', 'error')
        return redirect(url_for('sso'))

    session['apps'].append({'name': app_name, 'url': app_url})
    flash('    App added successfully', 'success')
    return redirect(url_for('sso'))

# Route to remove an app from the SSO page
@app.route('/remove_app/<int:app_index>')
def remove_app(app_index):
    if 'username' not in session:
        return redirect(url_for('login'))

    apps = session['apps']

    if app_index < 0 or app_index >= len(apps):
        flash('Invalid app index', 'error')
        return redirect(url_for('sso'))

    # Remove the app from the user's apps list
    del apps[app_index]
    flash('App removed successfully', 'success')
    return redirect(url_for('sso'))

# Ensure tables are created before running the app
with app.app_context():
    db.create_all()


# Check if the database file exists
if not os.path.exists('user_accounts.db'):
    # Create the database file by running the Flask application
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    app.run(debug=True)