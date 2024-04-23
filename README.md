**EffortlessIAM - Flask Authenticator App**

This Flask project is an authenticator application that allows users to securely manage and generate Time-based One-Time Passwords (TOTP) for two-factor authentication (2FA).

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Features**

User authentication with email and password

Adding and managing TOTP secrets for authentication

Dashboard to view TOTP tokens and remaining time

Simple and responsive web interface

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Prerequisites**

Before running this application, ensure you have the following installed:

Python 3.x
pip (Python package manager)
Flask
SQLAlchemy
Flask-Bcrypt
PyOTP

You can install the required Python packages using pip:

pip install flask flask_sqlalchemy flask_bcrypt pyotp logging

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Getting Started**

Clone the repository:

git clone https://github.com/yourusername/flask-authenticator.git

Navigate to the project directory:

cd flask-authenticator

Set up the virtual environment (optional but recommended):

python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

Install dependencies:

pip install -r requirements.txt

Set up the database:

flask db init
flask db migrate
flask db upgrade

Run the application:

flask run

Open a web browser and go to http://localhost:5000 to access the application.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Configuration**

The application can be configured via environment variables. Create a .env file in the project directory and define the following variables:

SECRET_KEY=your_secret_key_here
SQLALCHEMY_DATABASE_URI=sqlite:///user_accounts.db

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Usage**

Register a new account: Sign up with an email, password, and phone number.

Log in to the dashboard: Access your account and add new authentication methods.

Add a new authentication account: Enter the name and TOTP secret to associate with your account.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Contributing**

Contributions are welcome! If you have suggestions, improvements, or feature requests, please open an issue on GitHub.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**License**

This project is licensed under the MIT License.
