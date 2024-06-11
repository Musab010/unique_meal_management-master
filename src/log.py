import os
import csv
from datetime import datetime
from cryptography.fernet import Fernet
from encrypt_decrypt import encrypt_data, decrypt_data

LOG_FILE = 'data/logs.csv'
ENCRYPTED_LOG_FILE = 'data/encrypted_logs.csv'
KEY_FILE = 'data/secret.key'

def generate_key():
    """Genereer en sla een sleutel op voor encryptie."""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)

def load_key():
    """Laad de sleutel voor encryptie."""
    return open(KEY_FILE, 'rb').read()

if not os.path.exists(KEY_FILE):
    generate_key()

cipher = Fernet(load_key())

def get_next_log_number():
    """Bepaal het volgende lognummer door de bestaande logs te tellen."""
    if not os.path.exists(LOG_FILE):
        return 1
    with open(LOG_FILE, 'r') as file:
        reader = csv.reader(file)
        log_entries = list(reader)
        return len(log_entries) + 1

def log_activity(username, description, additional_info='', suspicious='No'):
    """Log een activiteit."""
    date = datetime.now().strftime('%d-%m-%Y')
    time = datetime.now().strftime('%H:%M:%S')
    log_number = get_next_log_number()
    
    # Versleutel de log informatie
    encrypted_username = encrypt_data(username)
    encrypted_description = encrypt_data(description)
    encrypted_additional_info = encrypt_data(additional_info)
    encrypted_suspicious = encrypt_data(suspicious)
    
    log_entry = [log_number, date, time, encrypted_username, encrypted_description, encrypted_additional_info, encrypted_suspicious]
    
    # Schrijf de log naar een CSV bestand
    with open(LOG_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(log_entry)
    
    # Versleutel de log file
    encrypt_log_file()

def encrypt_log_file():
    """Versleutel de log file."""
    with open(LOG_FILE, 'rb') as file:
        encrypted_data = cipher.encrypt(file.read())
    
    with open(ENCRYPTED_LOG_FILE, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

def decrypt_log_file():
    """Desleutel de log file en lees de inhoud."""
    if not os.path.exists(ENCRYPTED_LOG_FILE):
        return []
    
    with open(ENCRYPTED_LOG_FILE, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    
    decrypted_data = cipher.decrypt(encrypted_data).decode()
    
    logs = []
    reader = csv.reader(decrypted_data.splitlines())
    for idx, row in enumerate(reader):
        if len(row) == 7:  # Verwachte lengte met lognummer
            decrypted_row = [
                row[0],  # log number
                row[1],  # date
                row[2],  # time
                decrypt_data(row[3]),  # username
                decrypt_data(row[4]),  # description
                decrypt_data(row[5]),  # additional info
                decrypt_data(row[6])   # suspicious
            ]
            logs.append(decrypted_row)
        elif len(row) == 6:  # Oudere log zonder lognummer
            decrypted_row = [
                idx + 1,  # log number gebaseerd op de rij index
                row[0],  # date
                row[1],  # time
                decrypt_data(row[2]),  # username
                decrypt_data(row[3]),  # description
                decrypt_data(row[4]),  # additional info
                decrypt_data(row[5])   # suspicious
            ]
            logs.append(decrypted_row)
        else:
            print(f"Unexpected RowLength: {len(row)}. Row: {row}")
    
    return logs

def get_suspicious_logs():
    """Haal verdachte logs op."""
    logs = decrypt_log_file()
    suspicious_logs = [log for log in logs if log[6] == 'Yes']
    return suspicious_logs

def log_suspicious_activity(username, description, additional_info=''):
    """Log verdachte activiteiten."""
    log_activity(username, description, additional_info, suspicious='Yes')

