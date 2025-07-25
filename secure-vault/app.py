from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
import os, base64, hashlib, pymongo, yara
from Crypto.Cipher import AES, DES3, DES, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from logger import get_logger
from malware_analysis import analyze_with_virustotal

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database
client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client['secure_vault']
users = db['users']

# Logger
logger = get_logger()

# --- ENCRYPTION FUNCTIONS ---
def encrypt_data(data, key, method):
    key_bytes = hashlib.sha256(key.encode()).digest()
    if method == 'AES':
        cipher = AES.new(key_bytes[:16], AES.MODE_CBC)
        ct = cipher.encrypt(pad(data, AES.block_size))
        return cipher.iv + ct
    elif method == 'DES':
        cipher = DES.new(key_bytes[:8], DES.MODE_CBC)
        return cipher.iv + cipher.encrypt(pad(data, DES.block_size))
    elif method == '3DES':
        cipher = DES3.new(key_bytes[:24], DES3.MODE_CBC)
        return cipher.iv + cipher.encrypt(pad(data, DES3.block_size))
    elif method == 'Blowfish':
        cipher = Blowfish.new(key_bytes[:16], Blowfish.MODE_CBC)
        return cipher.iv + cipher.encrypt(pad(data, Blowfish.block_size))
    elif method in ['RC4', 'Base64']:
        return base64.b64encode(data)
    return data

def decrypt_data(data, key, method):
    key_bytes = hashlib.sha256(key.encode()).digest()
    try:
        if method == 'AES':
            iv, ct = data[:16], data[16:]
            cipher = AES.new(key_bytes[:16], AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size)
        elif method == 'DES':
            iv, ct = data[:8], data[8:]
            cipher = DES.new(key_bytes[:8], DES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), DES.block_size)
        elif method == '3DES':
            iv, ct = data[:8], data[8:]
            cipher = DES3.new(key_bytes[:24], DES3.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), DES3.block_size)
        elif method == 'Blowfish':
            iv, ct = data[:8], data[8:]
            cipher = Blowfish.new(key_bytes[:16], Blowfish.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), Blowfish.block_size)
        elif method in ['RC4', 'Base64']:
            return base64.b64decode(data)
    except:
        return b''

# --- MALWARE ANALYSIS (Deprecated) ---
def analyze_file_with_yara(filepath):
    rules_path = "malware_rules.yar"
    if not os.path.exists(rules_path):
        with open(rules_path, "w") as f:
            f.write('rule dummy_malware { condition: false }')
    rules = yara.compile(filepath=rules_path)
    matches = rules.match(filepath)
    return bool(matches)

# --- ROUTES ---
@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = hashlib.sha256(request.form['password'].encode()).hexdigest()
        user = users.find_one({'username': uname, 'password': pwd})
        logger.info(f"User: {uname} | Action: Login | Status: {'Success' if user else 'Fail'}")
        if user:
            session['username'] = uname
            return redirect('/menu')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = hashlib.sha256(request.form['password'].encode()).hexdigest()
        users.insert_one({'username': uname, 'password': pwd})
        logger.info(f"User: {uname} | Action: Register")
        return redirect('/login')
    return render_template('register.html')

@app.route('/menu', methods=['GET', 'POST'])
def menu():
    if 'username' not in session:
        return redirect('/login')

    files = os.listdir(app.config['UPLOAD_FOLDER'])

    if request.method == 'POST':
        action = request.form['action']
        uploaded_file = request.files.get('file')
        method = request.form.get('encryption')
        key = request.form.get('key') or 'defaultkey'

        filename = secure_filename(uploaded_file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if action == 'upload':
            uploaded_file.save(filepath)
            logger.info(f"User: {session['username']} | Action: Upload | File: {filename}")

        elif action == 'encrypt':
            data = uploaded_file.read()
            encrypted = encrypt_data(data, key, method)
            with open(filepath, 'wb') as f:
                f.write(encrypted)
            logger.info(f"User: {session['username']} | Action: Encrypt | File: {filename} | Method: {method}")

        elif action == 'decrypt':
            with open(filepath, 'rb') as f:
                enc = f.read()
            dec = decrypt_data(enc, key, method)
            with open(filepath.replace('.', '_decrypted.'), 'wb') as f:
                f.write(dec)
            logger.info(f"User: {session['username']} | Action: Decrypt | File: {filename} | Method: {method}")

        elif action == 'analyze':
            uploaded_file.save(filepath)
            result = analyze_with_virustotal(filepath, session['username'])
            logger.info(f"User: {session['username']} | Action: Malware Analysis | File: {filename} | Result: {result}")

        return redirect('/menu')

    return render_template('vault.html', files=files)

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    logger.info(f"User: {session.get('username', 'Unknown')} | Action: Logout")
    session.pop('username', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
