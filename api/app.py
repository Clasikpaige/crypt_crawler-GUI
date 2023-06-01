from flask import Flask, render_template, request
import os
import subprocess
import argparse
import pandas as pd
import binascii
from pywallet import wallet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from mnemonic import Mnemonic
from bitcoinlib.keys import BitcoinPrivateKey

app = Flask(__name__)

@app.route('/')
def home():
    return 'Hello, World!'

def generate_wordlist(count, output_file):
    mnemonic = Mnemonic("english")
    words = mnemonic.generate(strength=128)
    df = pd.DataFrame([words.split()], columns=['word'])
    df.to_csv(output_file, index=False)
    return words

def hash_wordlist(hash_type, wordlist_file):
    hash_command = f'john --wordlist={wordlist_file} --format={hash_type}'
    subprocess.run(hash_command, shell=True)

def generate_private_key(wordlist, target_hash):
    backend = default_backend()
    salt = os.urandom(16)
    password = None
    mnemonic = Mnemonic("english")
    if mnemonic.check(target_hash):
        password = target_hash.encode()
    else:
        return None
    if password:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        seed = mnemonic.to_seed(password)
        key = kdf.derive(seed)
        private_key = binascii.hexlify(key).decode()
        return private_key
    return None

def validate_private_key(private_key, target_address):
    key = BitcoinPrivateKey(private_key)
    address = key.public_key().address()
    return address == target_address

def recover_recovery_phrase(wordlist, target_address):
    for word in wordlist:
        seed = wallet.mnemonic_to_seed(word)
        recovered_wallet = wallet.create_wallet(network="BTC", seed=seed, children=1)
        recovered_address = recovered_wallet['address']
        
        if target_address == recovered_address:
            return word
    
    return None

@app.route('/generate_wordlist', methods=['GET', 'POST'])
def generate_wordlist_route():
    if request.method == 'POST':
        count = int(request.form['count'])
        output_file = request.form['output_file']
        wordlist_file = os.path.join('wordlist', output_file)
        words = generate_wordlist(count, wordlist_file)
        return f"Wordlist generated: {words}"
    else:
        return render_template('generate_wordlist.html')

@app.route('/hash_wordlist', methods=['GET', 'POST'])
def hash_wordlist_route():
    if request.method == 'POST':
        hash_type = request.form['hash_type']
        wordlist_file = request.form['wordlist_file']
        hash_wordlist(hash_type, wordlist_file)
        return "Wordlist hashed successfully!"
    else:
        return render_template('hash_wordlist.html')

@app.route('/generate_private_key', methods=['GET', 'POST'])
def generate_private_key_route():
    if request.method == 'POST':
        wordlist = request.form['wordlist']
        target_hash = request.form['target_hash']
        private_key = generate_private_key(wordlist, target_hash)
        if private_key:
            return f"Private key generated: {private_key}"
        else:
            return "No matching password found for the target hash."
    else:
        return render_template('generate_private_key.html')

@app.route('/validate_private_key', methods=['GET', 'POST'])
def validate_private_key_route():
    if request.method == 'POST':
        private_key = request.form['private_key']
        target_address = request.form['target_address']
        is_valid = validate_private_key(private_key, target_address)
        if is_valid:
            return "Private key is valid!"
        else:
            return "Generated private key is invalid."
    else:
        return render_template('validate_private_key.html')

@app.route('/recover_recovery_phrase', methods=['GET', 'POST'])
def recover_recovery_phrase_route():
    if request.method == 'POST':
        wordlist = request.form['wordlist']
        target_address = request.form['target_address']
        recovery_word = recover_recovery_phrase(wordlist, target_address)
        if recovery_word:
            return f"Recovered recovery phrase: {recovery_word}"
        else:
            return "Recovery phrase not found."
    else:
        return render_template('recover_recovery_phrase.html')

if __name__ == '__main__':
    app.run()
