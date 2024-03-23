from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, login_user, UserMixin, logout_user, login_required
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_cors import CORS  # Import Flask-CORS
import hashlib
import os
from random import randint

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_accounts.db'  # SQLite database
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'effortlessiam1@gmail.com'
app.config['MAIL_PASSWORD'] = 'djvf logu kihb fpvz'


mail = Mail(app)
db = SQLAlchemy(app)

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email_hash = db.Column(db.String(64), unique=True, nullable=False)  # Storing hashed email
    password_hash = db.Column(db.String(128), nullable=False)
    verified = db.Column(db.Boolean, nullable=False, default=False)
    verification_token = db.Column(db.String(32))
    password_vault = db.Column(db.JSON)

# Create the database tables
with app.app_context():
    db.create_all()

# Flask-Login LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Function to send email verification
def send_verification_email(email, verification_token):
    verification_link = url_for('verify_email', token=verification_token, _external=True)
    msg = Message('Email Verification', sender='your-email@example.com', recipients=[email])
    msg.body = f'Click the following link to verify your email: {verification_link}'
    mail.send(msg)

# Function to generate a secure token
def generate_token(data):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(data)

# Function to verify a token
def verify_token(token):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        data = serializer.loads(token, max_age=3600)  # Token valid for 1 hour
        return data
    except SignatureExpired:
        return None  # Token expired
    except BadSignature:
        return None  # Token invalid

# Before each request, initialize the list of apps in the session
@app.before_request
def before_request():
    if 'apps' not in session:
        session['apps'] = []

# Route to serve the homepage
@app.route('/')
def index():
    return render_template('index.html')

# Serve static files for Vue.js app
@app.route('/vue_app/<path:path>')
def serve_vue_app(path):
    return app.send_static_file(f'vue_app/{path}')

# Route to login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if email is registered and verified
        user = User.query.filter_by(email_hash=hashlib.sha256(email.encode()).hexdigest()).first()
        if user and user.verified:
            # Check if credentials are valid
            if check_password_hash(user.password_hash, password):
                # Set up session to keep the user logged in
                session['username'] = email
                session['token'] = generate_token({'email': email})
                # Redirect to the homepage
                return redirect('/')
            else:
                # If credentials are invalid, render login page with error message
                flash('Invalid email or password', 'error')
                return render_template('login.html')
        else:
            # If email is not registered or not verified, return message to verify email
            flash('Please verify your email to log in', 'error')
            return render_template('login.html')

    # If request method is GET, render the login page
    return render_template('login.html')

# Route for verifying email
@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    # Verify email verification token
    data = verify_token(token)
    if data and 'email' in data:
        email = data['email']
        user = User.query.filter_by(email_hash=hashlib.sha256(email.encode()).hexdigest()).first()
        if user:
            user.verified = True
            db.session.commit()
            flash('Email verification successful. You can now log in.', 'success')
            return redirect('/login')
    flash('Invalid or expired email verification link.', 'error')
    return redirect('/')

# Route to logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('token', None)
    return redirect('/login')

# Function to send MFA code via email
def send_mfa_code_email(email, mfa_code):
    msg = Message('MFA Code', sender='your-email@example.com', recipients=[email])
    msg.body = f'Your MFA code is: {mfa_code}'
    mail.send(msg)

# Route for MFA verification
@app.route('/verify_mfa', methods=['GET', 'POST'])
@login_required
def verify_mfa():
    if 'mfa_verified' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        mfa_code = request.form['mfa_code']
        # Verify MFA code - replace with your own MFA verification logic
        if mfa_code == session.get('mfa_code'):
            session['mfa_verified'] = True
            return redirect(url_for('index'))
        else:
            flash('Invalid MFA code', 'error')
            return render_template('verify_mfa.html')
    
    # Generate and send MFA code
    email = session.get('username')
    user = User.query.filter_by(email_hash=hashlib.sha256(email.encode()).hexdigest()).first()
    if user:
        # Generate MFA code and store it in the database
        mfa_code = ''.join(str(randint(0, 9)) for _ in range(6))
        user.password_vault['mfa_code'] = mfa_code  # Store MFA code in user's password vault
        db.session.commit()

        # Send MFA code via email (you may implement SMS or other methods)
        send_mfa_code_email(email, mfa_code)
        
        flash('MFA code sent to your email', 'success')
        return render_template('verify_mfa.html')
    else:
        flash('User not found', 'error')
        return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
