from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import pyotp
import time

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_accounts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
db = SQLAlchemy(app)
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    phone_number = db.Column(db.String(20))
    password_hash = db.Column(db.String(128), nullable=False)
    secrets = db.relationship('Secret', backref='user', lazy=True)

    def add_totp_secret(self, name, secret_value):
        new_secret = Secret(user_id=self.id, name=name, secret=secret_value)
        db.session.add(new_secret)
        db.session.commit()
        return new_secret

    def generate_totp(self, secret):
        totp = pyotp.TOTP(secret)
        current_time = int(time.time())
        remaining_seconds = 30 - (current_time % 30)
        token = totp.now()
        return token, remaining_seconds

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
        new_secret = Secret(user_id=self.id, name=name, secret=secret_value)
        db.session.add(new_secret)
        db.session.commit()
        return new_secret

@app.route('/')
def homepage():
    return redirect('/login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        phone_number = request.form['phone_number']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(email=email, password_hash=hashed_password, phone_number=phone_number)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        return redirect('/dashboard')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect('/dashboard')
        else:
            return "Invalid email or password"

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/login')

    user = User.query.get(user_id)
    totp_tokens = []
    for secret in user.secrets:
        token, remaining_seconds = user.generate_totp(secret.secret)
        totp_tokens.append({'name': secret.name, 'token': token, 'remaining_seconds': remaining_seconds})

    return render_template('dashboard.html', user=user, totp_tokens=totp_tokens)

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
            user.add_totp_secret(name=name, secret_value=secret)
            return redirect('/dashboard')
        else:
            return render_template('add_account.html', error_message='Invalid form data')

    elif request.method == 'GET':
        return render_template('add_account.html')
    
    return "Method Not Allowed", 405

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
