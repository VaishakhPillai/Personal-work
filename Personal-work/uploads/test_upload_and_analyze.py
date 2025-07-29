import requests

# Configuration
URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{URL}/login"
MENU_URL = f"{URL}/menu"
UPLOAD_FILE_PATH = "sample_test_file.txt"  # You can change this to any test file

# Step 1: Create a session to maintain cookies (e.g., login session)
session = requests.Session()

# Step 2: Login with test credentials
login_payload = {
    "username": "testuser",
    "password": "testpass"
}
response = session.post(LOGIN_URL, data=login_payload)
if "menu" not in response.url:
    print("[❌] Login failed. Please register the user first.")
    exit()

print("[✅] Logged in successfully.")

# Step 3: Create a sample file to upload
with open(UPLOAD_FILE_PATH, "w") as f:
    f.write("This is a harmless test file. Nothing malicious here.")

# Step 4: Upload the file and request analysis
with open(UPLOAD_FILE_PATH, "rb") as file:
    files = {"file": file}
    data = {
        "action": "analyze",       # Tell the server to analyze it
        "encryption": "",          # Not needed for analysis
        "key": ""                  # Not needed for analysis
    }
    response = session.post(MENU_URL, data=data, files=files)

# Step 5: Check result
if response.status_code == 200:
    print("[✅] File uploaded and analysis requested.")
else:
    print("[❌] Upload or analysis failed.")

