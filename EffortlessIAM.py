from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

import pyotp
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

def generate_secret():
    # Generate a random secret key
    return pyotp.random_base32()

def generate_qr_code(secret, name):
    # Generate a QR code URL for the secret
    return pyotp.totp.TOTP(secret).provisioning_uri(name)

def verify_token(secret, token):
    # Verify if the provided token is valid
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

@app.route('/generate_qr_code', methods=['POST'])
def generate_qr_code_api():
    data = request.get_json()
    secret = generate_secret()
    name = data.get('name', 'MyAccount')
    qr_code = generate_qr_code(secret, name)
    return jsonify({'secret': secret, 'qr_code': qr_code})

@app.route('/verify_token', methods=['POST'])
def verify_token_api():
    data = request.get_json()
    secret = data.get('secret')
    token = data.get('token')
    if verify_token(secret, token):
        return jsonify({'status': 'success', 'message': 'Token is valid!'})
    else:
        return jsonify({'status': 'error', 'message': 'Token is invalid'})

if __name__ == "__main__":
    app.run(debug=True)


@app.route('/generate_qr_code', methods=['GET', 'POST'])
def generate_qr_code_api():
    if request.method == 'POST':
        data = request.get_json()
        secret = generate_secret()
        name = data.get('name', 'MyAccount')
        qr_code = generate_qr_code(secret, name)
        return jsonify({'secret': secret, 'qr_code': qr_code})
    return render_template('generate_qr_code.html')

@app.route('/verify_token', methods=['GET', 'POST'])
def verify_token_api():
    if request.method == 'POST':
        data = request.get_json()
        secret = data.get('secret')
        token = data.get('token')
        if verify_token(secret, token):
            return jsonify({'status': 'success', 'message': 'Token is valid!'})
        else:
            return jsonify({'status': 'error', 'message': 'Token is invalid'})
    return render_template('verify_token.html')

if __name__ == "__main__":
    app.run(debug=True)
