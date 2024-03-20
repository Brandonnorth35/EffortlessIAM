from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash, render_template
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import secrets
import pyotp
import qrcode
import json
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'effortlessiam1@gmail.com'
app.config['MAIL_PASSWORD'] = 'djvf logu kihb fpvz'

mail = Mail(app)

# Function to send email verification
def send_verification_email(email, verification_token):
    verification_link = url_for('verify_email', token=verification_token, _external=True)
    
    # Render the HTML template with the verification link
    html_content = render_template('msg.html', verification_link=verification_link)
    
    # Construct the email message
    msg = Message('Email Verification', sender='your-email@example.com', recipients=[email])
    msg.body = f'Click the following link to verify your email: {verification_link}'
    msg.html = html_content
    
    # Send the email
    mail.send(msg)


# Load user accounts from JSON file
with open('user_accounts.json') as f:
    users = json.load(f)

# Function to send email verification
def send_verification_email(email, token):
    msg = Message('Email Verification', sender='your-email@example.com', recipients=[email])
    msg.body = f'Your verification token is: {token}'
    mail.send(msg)

# Function to verify a token given a secret key and token
def verify_token(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

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
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if email is registered and verified
        if email in users and users[email]['verified']:
            # Check if credentials are valid
            if check_password_hash(users[email]['password'], password):
                # Set up session to keep the user logged in
                session['username'] = email
                session['password_vault'] = users[email]['password_vault']
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

# Route to signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email in users:
            # If email already exists, render signup page with error message
            flash('Email already exists', 'error')
            return render_template('signup.html')

        # Generate email verification token
        verification_token = secrets.token_hex(16)
        # Send verification email
        send_verification_email(email, verification_token)
        # Add the user to the database with unverified status and hashed password
        users[email] = {'password': generate_password_hash(password), 'verified': False, 'verification_token': verification_token, 'password_vault': []}
        with open('user_accounts.json', 'w') as f:
            json.dump(users, f)
        # Redirect to the login page after successful signup
        flash('Signup successful. Please verify your email.', 'success')
        return render_template('login.html')

    # If it's a GET request or there's no error, render the signup page without any message
    return render_template('signup.html')

# Route for verifying email
@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    # Verify email verification token
    try:
        # Decode and verify the token
        # Here, you would verify the token against the one stored in the database
        # If token is valid, mark the user's email as verified
        # Example implementation using URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.secret_key)
        email = serializer.loads(token, salt='email-confirm', max_age=3600)  # Valid for 1 hour
        users[email]['verified'] = True
        flash('Email verification successful. You can now log in.', 'success')
        return redirect(url_for('login'))
    except SignatureExpired:
        # Token expired
        flash('Email verification link has expired.', 'error')
    except BadSignature:
        # Token invalid
        flash('Invalid email verification link.', 'error')

    return redirect(url_for('home'))

# Route to password vault page
@app.route('/password_vault', methods=['GET', 'POST'])
def password_vault():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        page_name = request.form['page_name']
        page_url = request.form['page_url']
        username = request.form['username']
        password = request.form['password']

        # Add entry to the password vault
        session['password_vault'].append({'page_name': page_name, 'page_url': page_url, 'username': username, 'password': password})

        # Update user's password vault in the JSON file
        users[session['username']]['password_vault'] = session['password_vault']
        with open('user_accounts.json', 'w') as f:
            json.dump(users, f)

    return render_template('password_vault.html', vault_entries=session['password_vault'])

# Route to logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('password_vault', None)
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)