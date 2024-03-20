from flask import Flask, request, session, redirect, url_for, flash, render_template
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
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

# Load user accounts from JSON file
with open('user_accounts.json') as f:
    users = json.load(f)

# Function to send email verification
def send_verification_email(email, verification_token):
    verification_link = url_for('verify_email', token=verification_token, _external=True)
    
    # Construct the email message
    msg = Message('Email Verification', sender='your-email@example.com', recipients=[email])
    msg.body = f'Click the following link to verify your email: {verification_link}'
    
    # Send the email
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
        users[email]['verified'] = True
        flash('Email verification successful. You can now log in.', 'success')
        return redirect('/login')
    else:
        flash('Invalid or expired email verification link.', 'error')
        return redirect('/')

# Route to logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('token', None)
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
    flash('App added successfully', 'success')
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

if __name__ == "__main__":
    app.run(debug=True)
