from flask import Flask, render_template, request, redirect, session, send_from_directory
import os
import logging
from werkzeug.utils import secure_filename
from encryption_utils import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt, tdes_encrypt, tdes_decrypt, fernet_encrypt, fernet_decrypt, base64_encode, base64_decode, blowfish_encrypt, blowfish_decrypt, rc4_encrypt, rc4_decrypt
from malware_analysis import analyze_with_virustotal
from pymongo import MongoClient
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler('vault_activity_log.txt')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['vault_db']
users = db['users']
logs = db['logs']

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.find_one({'username': username, 'password': password})
        if user:
            session['username'] = username
            logger.info(f"User: {username} logged in")
            logs.insert_one({'username': username, 'action': 'login', 'timestamp': datetime.now()})
            return redirect('/menu')
        else:
            return 'Invalid credentials'
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if users.find_one({'username': username}):
            return 'User already exists'
        users.insert_one({'username': username, 'password': password})
        return redirect('/login')
    return render_template('register.html')

@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        logger.info(f"User: {username} logged out")
        logs.insert_one({'username': username, 'action': 'logout', 'timestamp': datetime.now()})
    session.pop('username', None)
    return redirect('/login')

@app.route('/uploads/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/menu', methods=['GET', 'POST'])
def menu():
    if 'username' not in session:
        return redirect('/login')

    files = os.listdir(app.config['UPLOAD_FOLDER'])
    step = request.form.get('step') or 'choose_action'
    selected_action = request.form.get('action')

    if request.method == 'POST':
        if step == 'choose_action':
            return render_template('vault.html', files=files, step=selected_action)

        uploaded_file = request.files.get('file')
        filename = secure_filename(uploaded_file.filename) if uploaded_file else None
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename) if filename else None
        method = request.form.get('encryption')
        key = request.form.get('key') or 'defaultkey'

        if selected_action == 'upload' and uploaded_file:
            uploaded_file.save(filepath)
            logger.info(f"User: {session['username']} | Action: Upload | File: {filename}")
            logs.insert_one({'username': session['username'], 'action': 'upload', 'file': filename, 'timestamp': datetime.now()})

        elif selected_action == 'encrypt' and uploaded_file:
            data = uploaded_file.read()
            encrypted = encrypt_data(data, key, method)
            with open(filepath, 'wb') as f:
                f.write(encrypted)
            logger.info(f"User: {session['username']} | Action: Encrypt | File: {filename} | Method: {method}")
            logs.insert_one({'username': session['username'], 'action': 'encrypt', 'file': filename, 'method': method, 'timestamp': datetime.now()})

        elif selected_action == 'decrypt' and uploaded_file:
            uploaded_file.save(filepath)
            with open(filepath, 'rb') as f:
                enc = f.read()
            dec = decrypt_data(enc, key, method)
            with open(filepath.replace('.', '_decrypted.'), 'wb') as f:
                f.write(dec)
            logger.info(f"User: {session['username']} | Action: Decrypt | File: {filename} | Method: {method}")
            logs.insert_one({'username': session['username'], 'action': 'decrypt', 'file': filename, 'method': method, 'timestamp': datetime.now()})

        elif selected_action == 'analyze' and uploaded_file:
            uploaded_file.save(filepath)
            result = analyze_with_virustotal(filepath, session['username'])
            logger.info(f"User: {session['username']} | Action: Malware Analysis | File: {filename} | Result: {result}")
            logs.insert_one({'username': session['username'], 'action': 'analyze', 'file': filename, 'result': result, 'timestamp': datetime.now()})

        elif selected_action == 'open_case':
            logger.info(f"User: {session['username']} | Action: Open Case")
            logs.insert_one({'username': session['username'], 'action': 'open_case', 'timestamp': datetime.now()})

        elif selected_action == 'view_logs':
            user_logs = list(logs.find({'username': session['username']}))
            return render_template('vault.html', files=files, step='view_logs', logs=user_logs)

        elif selected_action == 'view_files':
            return render_template('vault.html', files=files, step='view_files')

        return redirect('/menu')

    return render_template('vault.html', files=files, step='choose_action')

def encrypt_data(data, key, method):
    if method == 'AES':
        return aes_encrypt(data, key)
    elif method == 'DES':
        return des_encrypt(data, key)
    elif method == '3DES':
        return tdes_encrypt(data, key)
    elif method == 'Fernet':
        return fernet_encrypt(data, key.encode())
    elif method == 'Base64':
        return base64_encode(data)
    elif method == 'Blowfish':
        return blowfish_encrypt(data, key)
    elif method == 'RC4':
        return rc4_encrypt(data, key)
    return data

def decrypt_data(data, key, method):
    if method == 'AES':
        return aes_decrypt(data, key)
    elif method == 'DES':
        return des_decrypt(data, key)
    elif method == '3DES':
        return tdes_decrypt(data, key)
    elif method == 'Fernet':
        return fernet_decrypt(data, key.encode())
    elif method == 'Base64':
        return base64_decode(data)
    elif method == 'Blowfish':
        return blowfish_decrypt(data, key)
    elif method == 'RC4':
        return rc4_decrypt(data, key)
    return data

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
