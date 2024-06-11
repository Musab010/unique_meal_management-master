from datetime import datetime
from encrypt_decrypt import encrypt_data, decrypt_data
from log import log_activity, log_suspicious_activity
from utils import hash_password  # Gebruik de hash_password-functie vanuit utils
import sqlite3
from sqlite3 import Error
import logging
import re

# Functies voor validatie
def is_valid_username(username):
    """Controleer of de gebruikersnaam voldoet aan de vereiste regels."""
    if len(username) < 8 or len(username) > 10:
        print("De gebruikersnaam moet tussen 8 en 10 tekens lang zijn.")
        return False
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_'.]*$", username):
        print("De gebruikersnaam moet beginnen met een letter of underscore (_) en mag alleen letters, cijfers, underscores (_), apostrof (') of punten (.) bevatten.")
        return False
    return True

def is_valid_password(password):
    """Controleer of het wachtwoord voldoet aan de vereiste regels."""
    if len(password) < 12 or len(password) > 30:
        print("Het wachtwoord moet tussen 12 en 30 tekens lang zijn.")
        return False
    if not re.search(r"[a-z]", password):  # minstens één kleine letter
        print("Het wachtwoord moet minstens één kleine letter bevatten.")
        return False
    if not re.search(r"[A-Z]", password):  # minstens één hoofdletter
        print("Het wachtwoord moet minstens één hoofdletter bevatten.")
        return False
    if not re.search(r"\d", password):  # minstens één cijfer
        print("Het wachtwoord moet minstens één cijfer bevatten.")
        return False
    if not re.search(r"[~!@#$%&_\-+=`|\(){}[\]:;'<>,.?/]", password):  # minstens één speciaal teken
        print("Het wachtwoord moet minstens één speciaal teken bevatten.")
        return False
    return True

def validate_login(conn, username, password):
    try:
        cursor = conn.cursor()
        
        # Haal alle gebruikers op en ontsleutel de gebruikersnamen
        cursor.execute("SELECT id, username, password, role FROM users")
        users = cursor.fetchall()
        
        for user in users:
            decrypted_username = decrypt_data(user[1])  # Ontsleutel de gebruikersnaam
            
            if decrypted_username == username:
                # Vergelijk gehasht wachtwoord
                hashed_password = hash_password(password)
                
                if user[2] == hashed_password:
                    return user[0], user[3]  # retourneer user_id en role
        
        return None  # retourneer None als de inloggegevens ongeldig zijn
    except Exception as e:
        logging.error(f"Fout bij inloggen: {e}")
        return None

# Voeg logging toe voor gebruikersbeheer
def add_user(conn, username, password, role, first_name, last_name):
    from database import insert_user  # Importeer alleen binnen de functie
    user_id = insert_user(conn, username, password, role, first_name, last_name)
    if user_id:
        log_activity(username, "User added", f"Role: {role}, Name: {first_name} {last_name}")
    else:
        log_suspicious_activity(username, "Failed to add user", f"Role: {role}, Name: {first_name} {last_name}")

def delete_user(conn, user_id):
    from database import remove_user  # Importeer alleen binnen de functie
    if remove_user(conn, user_id):
        log_activity("system", "User deleted", f"User ID: {user_id}")
    else:
        log_suspicious_activity("system", "Failed to delete user", f"User ID: {user_id}")

def username_exists(conn, username):
    """Controleer of een gegeven gebruikersnaam al bestaat in de database."""
    try:
        sql = "SELECT username FROM users"
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()

        for row in rows:
            decrypted_username = decrypt_data(row[0])
            if decrypted_username == username:
                return True
        return False
    except Error as e:
        logging.error(f"Error checking for existing username: {e}")
        return False

def add_user_prompt(conn, default_role=None):
    """Prompt de gebruiker om een nieuwe gebruiker toe te voegen met een vastgestelde rol."""
    while True:
        username = input("Gebruikersnaam: ")
        if not is_valid_username(username):
            print("Ongeldige gebruikersnaam. Zorg ervoor dat de gebruikersnaam voldoet aan de vereisten.")
            continue

        # Check of de gebruikersnaam al bestaat
        if username_exists(conn, username):
            print("Deze gebruikersnaam bestaat al. Kies een andere gebruikersnaam.")
            continue
        break

    while True:
        password = input("Wachtwoord: ")
        if not is_valid_password(password):
            print("Ongeldig wachtwoord. Zorg ervoor dat het wachtwoord voldoet aan de vereisten.")
            continue
        break

    first_name = input("Voornaam: ")
    last_name = input("Achternaam: ")

    # Als default_role niet is opgegeven, vraag dan de gebruiker om een rol in te voeren
    role = default_role if default_role else input("Rol: ")

    encrypted_username = encrypt_data(username)  # Encrypt de gebruikersnaam voor opslag
    hashed_password = hash_password(password)    # Hash het wachtwoord voor opslag
    encrypted_first_name = encrypt_data(first_name)
    encrypted_last_name = encrypt_data(last_name)

    try:
        sql = """INSERT INTO users (username, password, role, first_name, last_name, registration_date)
                 VALUES (?, ?, ?, ?, ?, ?)"""
        cur = conn.cursor()
        cur.execute(sql, (encrypted_username, hashed_password, role, encrypted_first_name, encrypted_last_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        log_activity(username, "User added via prompt", f"Role: {role}, Name: {first_name} {last_name}")
        print(f"Gebruiker {username} succesvol toegevoegd.")
    except Error as e:
        logging.error(f"Error adding user: {e}")
        log_suspicious_activity(username, "Failed to add user via prompt", f"Role: {role}, Name: {first_name} {last_name}")

def add_system_admin_prompt(conn):
    """Prompt de gebruiker om een nieuwe systeembeheerder toe te voegen."""
    print("Voeg nieuwe systeembeheerder toe.")
    add_user_prompt(conn, default_role='system_admin')  # Gebruik 'system_admin' als vaste rol

def add_consultant_prompt(conn):
    """Prompt de gebruiker om een nieuwe consultant toe te voegen."""
    print("Voeg nieuwe consultant toe.")
    add_user_prompt(conn, default_role='consultant')  # Gebruik 'consultant' als vaste rol

def update_password(conn, user_id):
    """Update het wachtwoord van de huidige gebruiker."""
    while True:
        new_password = input("Voer uw nieuwe wachtwoord in: ")
        if is_valid_password(new_password):
            break

    hashed_password = hash_password(new_password)

    try:
        # Haal de gebruikersnaam op van de huidige gebruiker
        sql_get_username = "SELECT username FROM users WHERE id=?"
        cur = conn.cursor()
        cur.execute(sql_get_username, (user_id,))
        row = cur.fetchone()

        if row:
            username = decrypt_data(row[0])  # Ontsleutel de gebruikersnaam

            # Update het wachtwoord voor de gevonden gebruiker
            sql_update = "UPDATE users SET password=? WHERE id=?"
            cur.execute(sql_update, (hashed_password, user_id))
            conn.commit()
            log_activity(username, "Password updated", "User updated their password")
            print(f"Wachtwoord voor gebruiker {username} succesvol bijgewerkt.")
        else:
            print("Gebruiker niet gevonden.")
            logging.error("Failed to find user for password update.")

    except Error as e:
        logging.error(f"Error updating password: {e}")
        log_suspicious_activity("system", "Failed to update password", f"Attempted to update password for user ID {user_id} with error: {e}")

def list_users(conn):
    """Geef een lijst van alle gebruikers en hun rollen."""
    try:
        sql = "SELECT username, role FROM users"
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()

        for row in rows:
            try:
                decrypted_username = decrypt_data(row[0])  # Ontsleutel de gebruikersnaam
                print(f"Gebruikersnaam: {decrypted_username}, Rol: {row[1]}")
            except Exception as e:
                logging.error(f"Error decrypting data: {row[0]}. Exception: {e}")
                print(f"Gebruikersnaam: [gehashed], Rol: {row[1]}")
    except Error as e:
        logging.error(f"Error listing users: {e}")

def update_user_prompt(conn):
    """Prompt de gebruiker om een bestaande gebruiker bij te werken."""
    while True:
        username = input("Voer de huidige gebruikersnaam in van de gebruiker die u wilt bijwerken: ")
        if is_valid_username(username):
            break

    while True:
        new_username = input("Nieuwe gebruikersnaam: ")
        if not is_valid_username(new_username):
            print("Ongeldige nieuwe gebruikersnaam. Zorg ervoor dat de gebruikersnaam voldoet aan de vereisten.")
            continue
        if username_exists(conn, new_username):
            print("Deze nieuwe gebruikersnaam bestaat al. Kies een andere gebruikersnaam.")
            continue
        break

    first_name = input("Nieuwe voornaam: ")
    last_name = input("Nieuwe achternaam: ")

    try:
        # Haal alle gebruikers op en decrypt de gebruikersnamen om de juiste gebruiker te vinden
        sql_fetch_all = "SELECT id, username FROM users"
        cur = conn.cursor()
        cur.execute(sql_fetch_all)
        rows = cur.fetchall()

        user_id = None
        encrypted_current_username = None
        encrypted_new_username = encrypt_data(new_username)

        for row in rows:
            decrypted_username = decrypt_data(row[1])
            if decrypted_username == username:
                user_id = row[0]
                encrypted_current_username = row[1]
                break

        if user_id:
            # Update de gebruiker op basis van user_id
            sql_update = "UPDATE users SET username=?, first_name=?, last_name=? WHERE id=?"
            cur.execute(sql_update, (encrypted_new_username, first_name, last_name, user_id))
            conn.commit()

            log_activity(username, "User updated", f"Username changed to {new_username}, Name updated to {first_name} {last_name}")
            print(f"Gebruiker {username} succesvol bijgewerkt naar {new_username}.")
        else:
            print(f"Gebruiker {username} niet gevonden.")
            log_suspicious_activity(username, "Failed to update user", f"Attempted to update non-existent user {username}")
    except Error as e:
        logging.error(f"Error updating user: {e}")
        log_suspicious_activity(username, "Failed to update user", f"Attempted to update {username} with error: {e}")

def delete_user_prompt(conn):
    """Prompt de gebruiker om een bestaande gebruiker te verwijderen."""
    while True:
        username = input("Voer de gebruikersnaam in van de gebruiker die u wilt verwijderen: ")
        if is_valid_username(username):
            break
    encrypted_username = None

    try:
        # Haal alle gebruikers op en decrypt deze om te vinden wie verwijderd moet worden
        sql = "SELECT username FROM users"
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()

        for row in rows:
            decrypted_username = decrypt_data(row[0])
            if decrypted_username == username:
                encrypted_username = row[0]
                break

        if encrypted_username:
            sql_delete = "DELETE FROM users WHERE username=?"
            cur.execute(sql_delete, (encrypted_username,))
            conn.commit()
            log_activity(username, "User deleted", f"User {username} was deleted")
            print(f"Gebruiker {username} succesvol verwijderd.")
        else:
            print(f"Gebruiker {username} niet gevonden.")
    except Error as e:
        logging.error(f"Error deleting user: {e}")
        log_suspicious_activity(username, "Failed to delete user", f"Attempted to delete {username}")

def reset_user_password(conn):
    """Reset het wachtwoord van een bestaande gebruiker."""
    while True:
        username = input("Voer de gebruikersnaam in van de gebruiker waarvan u het wachtwoord wilt resetten: ")
        if is_valid_username(username):
            break

    while True:
        new_password = input("Voer het nieuwe wachtwoord in: ")
        if is_valid_password(new_password):
            break
    
    hashed_password = hash_password(new_password)

    try:
        # Haal alle gebruikers op en decrypt de gebruikersnamen om de juiste gebruiker te vinden
        sql_fetch_all = "SELECT id, username FROM users"
        cur = conn.cursor()
        cur.execute(sql_fetch_all)
        rows = cur.fetchall()

        user_id = None
        encrypted_username = None

        for row in rows:
            decrypted_username = decrypt_data(row[1])
            if decrypted_username == username:
                user_id = row[0]
                encrypted_username = row[1]
                break

        if user_id:
            # Reset het wachtwoord voor de gevonden gebruiker
            sql_update = "UPDATE users SET password=? WHERE id=?"
            cur.execute(sql_update, (hashed_password, user_id))
            conn.commit()
            log_activity(username, "Password reset", f"Password for {username} was reset")
            print(f"Wachtwoord voor gebruiker {username} succesvol gereset.")
        else:
            print(f"Gebruiker {username} niet gevonden.")
            log_suspicious_activity(username, "Failed to reset password", f"Attempted to reset password for non-existent user {username}")
    except Error as e:
        logging.error(f"Error resetting password: {e}")
        log_suspicious_activity(username, "Failed to reset password", f"Attempted to reset password for {username} with error: {e}")

def update_admin_prompt(conn):
    """Prompt de gebruiker om een systeembeheerder bij te werken."""
    while True:
        username = input("Voer de huidige gebruikersnaam in van de systeembeheerder die u wilt bijwerken: ")
        if is_valid_username(username):
            break

    first_name = input("Nieuwe voornaam: ")
    last_name = input("Nieuwe achternaam: ")

    while True:
        new_username = input("Nieuwe gebruikersnaam: ")
        if not is_valid_username(new_username):
            print("Ongeldige nieuwe gebruikersnaam. Zorg ervoor dat de gebruikersnaam voldoet aan de vereisten.")
            continue
        if username_exists(conn, new_username):
            print("Deze nieuwe gebruikersnaam bestaat al. Kies een andere gebruikersnaam.")
            continue
        break

    try:
        # Haal alle gebruikers op en decrypt de gebruikersnamen om de juiste gebruiker te vinden
        sql_fetch_all = "SELECT id, username, role FROM users"
        cur = conn.cursor()
        cur.execute(sql_fetch_all)
        rows = cur.fetchall()

        user_id = None
        encrypted_current_username = None
        encrypted_new_username = encrypt_data(new_username)

        for row in rows:
            decrypted_username = decrypt_data(row[1])
            if decrypted_username == username:
                user_id = row[0]
                encrypted_current_username = row[1]
                role = row[2]
                break

        if user_id:
            if role != 'system_admin':
                print("Deze functie is alleen beschikbaar voor systeembeheerder accounts.")
                return

            # Update de systeembeheerder op basis van user_id
            sql_update = "UPDATE users SET username=?, first_name=?, last_name=? WHERE id=?"
            cur.execute(sql_update, (encrypted_new_username, encrypt_data(first_name), encrypt_data(last_name), user_id))
            conn.commit()

            log_activity(username, "System Admin updated", f"Username changed to {new_username}, Name updated to {first_name} {last_name}")
            print(f"Systeembeheerder {username} succesvol bijgewerkt naar {new_username}.")
        else:
            print(f"Systeembeheerder {username} niet gevonden.")
            log_suspicious_activity(username, "Failed to update system admin", f"Attempted to update non-existent system admin {username}")
    except Error as e:
        logging.error(f"Error updating system admin: {e}")
        log_suspicious_activity(username, "Failed to update system admin", f"Attempted to update system admin {username} with error: {e}")

def delete_admin_prompt(conn):
    """Prompt de gebruiker om een systeembeheerder account te verwijderen."""
    while True:
        username = input("Voer de gebruikersnaam in van de systeembeheerder die u wilt verwijderen: ")
        if is_valid_username(username):
            break
    encrypted_username = None

    try:
        # Haal alle gebruikers op en decrypt deze om te vinden wie verwijderd moet worden
        sql = "SELECT id, username, role FROM users"
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()

        user_id = None
        for row in rows:
            decrypted_username = decrypt_data(row[1])
            if decrypted_username == username:
                encrypted_username = row[1]
                role = row[2]
                user_id = row[0]
                break

        if user_id:
            if role != 'system_admin':
                print("Deze functie is alleen beschikbaar voor systeembeheerder accounts.")
                return

            sql_delete = "DELETE FROM users WHERE id=?"
            cur.execute(sql_delete, (user_id,))
            conn.commit()
            log_activity(username, "System Admin deleted", f"System Admin {username} was deleted")
            print(f"Systeembeheerder {username} succesvol verwijderd.")
        else:
            print(f"Systeembeheerder {username} niet gevonden.")
    except Error as e:
        logging.error(f"Error deleting system admin: {e}")
        log_suspicious_activity(username, "Failed to delete system admin", f"Attempted to delete {username}")

def reset_admin_password_prompt(conn):
    """Prompt de superadmin om het wachtwoord van een systeembeheerder te resetten."""
    while True:
        username = input("Voer de gebruikersnaam in van de systeembeheerder waarvan u het wachtwoord wilt resetten: ")
        if is_valid_username(username):
            break

    try:
        # Haal alle systeembeheerders op en decrypt de gebruikersnamen om de juiste te vinden
        sql_fetch_all = "SELECT id, username, role FROM users WHERE role='system_admin'"
        cur = conn.cursor()
        cur.execute(sql_fetch_all)
        rows = cur.fetchall()

        user_id = None
        for row in rows:
            decrypted_username = decrypt_data(row[1])
            if decrypted_username == username:
                user_id = row[0]
                break

        if user_id:
            while True:
                new_password = input("Voer het nieuwe wachtwoord in: ")
                if is_valid_password(new_password):
                    break

            hashed_password = hash_password(new_password)

            # Reset het wachtwoord voor de gevonden systeembeheerder
            sql_update = "UPDATE users SET password=? WHERE id=?"
            cur.execute(sql_update, (hashed_password, user_id))
            conn.commit()
            log_activity(username, "System Admin password reset", f"Password for system admin {username} was reset")
            print(f"Wachtwoord voor systeembeheerder {username} succesvol gereset.")
        else:
            print(f"Systeembeheerder {username} niet gevonden.")
            log_suspicious_activity(username, "Failed to reset password for system admin", f"Attempted to reset password for non-existent system admin {username}")
    except Error as e:
        logging.error(f"Error resetting password for system admin: {e}")
        log_suspicious_activity(username, "Failed to reset password for system admin", f"Attempted to reset password for {username} with error: {e}")
