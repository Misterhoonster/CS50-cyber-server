import os
import json
import hashlib
from flask import Flask, request, jsonify, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random

app = Flask(__name__)

# Encryption configuration
AES_BLOCK_SIZE = 16

def hash(key):
    """Hash using SHA-256 and return the first 16 bytes (AES-128 key)."""
    hashed = hashlib.sha256(key.encode()).digest()
    return hashed[:AES_BLOCK_SIZE]

def generate_letter_mapping(harvard_id):
    # Step 1: Hash the Harvard ID
    seed = hash(harvard_id)
    
    # Step 2: Generate a random permutation of letters
    letters = list("abcdefghijklmnopqrstuvwxyz")
    random.seed(seed)  # Use the hash integer as the seed
    random.shuffle(letters)  # Shuffle the letters
    
    # Step 3: Create the mapping
    mapping = {letter: permuted_letter for letter, permuted_letter in zip("abcdefghijklmnopqrstuvwxyz", letters)}
    
    return mapping

def ecb(text, student_id): 
    ecb_map = generate_letter_mapping(student_id)
    cipher_text = ""
    for char in text:
        if char.isalpha():
            if char in ecb_map:
                cipher_text += ecb_map[char]
        else:
            cipher_text += char
    return cipher_text

def get_excerpt(student_id):
    # Step 1: Read excerpts from the JSON file
    with open("excerpts.json", "r") as f:
        data = json.load(f)

    # Extract 'excerpt' values
    excerpts = [item['excerpt'] for item in data if 'excerpt' in item]
    
    # Step 2: Hash the Harvard ID
    seed = hash(student_id)
    
    # Step 4: Use the seed to pick a random excerpt
    random.seed(seed)  # Seed the random generator
    chosen_excerpt = random.choice(excerpts)  # Randomly select an excerpt

    return chosen_excerpt

# @app.route('/')
# def home():
#     """Homepage with a form to download the encrypted passwords file."""
#     return '''
#     <form action="/download" method="post">
#         <label for="name">Enter your name (no caps, no spaces):</label>
#         <input type="text" id="name" name="name" required>
#         <button type="submit">Download Passwords</button>
#     </form>
#     '''

@app.route('/download', methods=['POST'])
def download():
    """Encrypt and provide the passwords file for download."""
    student_id = request.form.get('id')

    # Validate input
    if not student_id or not student_id.isdigit():
        return "Invalid name. Use only lowercase letters without spaces.", 400

    # Load passwords from passwords.txt
    with open("passwords.txt", "r") as file:
        passwords = file.read().splitlines()

    # Randomly select a password using the hash of student ID as a seed
    key = hash(student_id)
    random.seed(key)
    selected_password = random.choice(passwords)

    # Hash the selected password using SHA-256
    hashed_password = hashlib.sha256(selected_password.encode()).hexdigest()

    # Update plaintext_passwords
    plaintext_passwords = f"davidjmalan:{hashed_password}"

    encrypted_filename = "passwords.db"

    # Encrypt using AES-128
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(plaintext_passwords.encode(), AES_BLOCK_SIZE))

    # Save the encrypted file
    with open(encrypted_filename, "wb") as f:
        f.write(iv + encrypted_data)

    # Provide the file for download
    return send_file(encrypted_filename, as_attachment=True)

@app.route('/fetch', methods=['GET'])
def fetch_key():
    """Return the secret key (hashed name) in a JSON response."""
    student_id = request.args.get('id')

    # Validate input
    if not student_id or not student_id.isdigit():
        return jsonify({"error": "Invalid name. Use only lowercase letters without spaces."}), 400

    # Return the hashed key
    secret_key = hash(student_id)
    return jsonify({"secret_key": secret_key.hex()})

@app.route('/get_text', methods=['GET'])
def get_text():
    """Return a randomly selected text from texts.txt."""
    
    student_id = request.args.get('id')
    
    # Validate input: Ensure student_id is provided and is numeric
    if not student_id or not student_id.isdigit():
        return jsonify({"error": "Invalid ID. Please provide a numeric Harvard ID."}), 400

    try:
        chosen_excerpt = get_excerpt(student_id)  # Randomly select an excerpt
        encrypted_text = ecb(chosen_excerpt, student_id)
        
        # Return the selected text as JSON response
        return jsonify({"response": encrypted_text})
    
    except FileNotFoundError:
        return jsonify({"error": "Please try again!"}), 500


@app.route('/check1', methods=['GET'])
def check1():
    """
    Check if the provided ID and text match the mapping in mapping.txt.
    """
    student_id = request.args.get('id')
    submitted_text = request.args.get('text')

    # Validate input
    if not student_id or not submitted_text:
        return jsonify({"error": "ID and text are required."}), 400
    
    try:
        chosen_excerpt = get_excerpt(student_id)
        if chosen_excerpt == submitted_text:
            return jsonify({"response": True})
        else:
            return jsonify({"response": False})
    except Exception as e:
        print(f"Error while reading the mapping")
        return False

@app.route('/check2', methods=['GET'])
def check2():
    """
    Check if the provided ID and text match the mapping in mapping.txt.
    """
    student_id = request.args.get('id')
    guess_password = request.args.get('password')

    # Validate input
    if not student_id or not guess_password:
        return jsonify({"error": "ID and text are required."}), 400
    
    with open("passwords.txt", "r") as file:
        passwords = file.read().splitlines()

    # Randomly select a password using the hash of student ID as a seed
    key = hash(student_id)
    random.seed(key)
    real_password = random.choice(passwords)
    
    if guess_password == real_password:
        return jsonify({"response": True})
    else:
        return jsonify({"response": False})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
