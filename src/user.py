from datetime import datetime
from encrypt_decrypt import encrypt_data, decrypt_data
from log import log_activity, log_suspicious_activity
from utils import hash_password  # Use the hash_password function from utils
import sqlite3
from sqlite3 import Error
import logging
import re

# Validation functions
def is_valid_username(username):
    """Check if the username meets the required rules."""
    if len(username) < 8 or len(username) > 10:
        print("The username must be between 8 and 10 characters long.")
        return False
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_'.]*$", username):
        print("The username must start with a letter or underscore (_) and can only contain letters, digits, underscores (_), apostrophes (') or dots (.)")
        return False
    return True

def is_valid_password(password):
    """Check if the password meets the required rules."""
    if len(password) < 12 or len(password) > 30:
        print("The password must be between 12 and 30 characters long.")
        return False
    if not re.search(r"[a-z]", password):  # at least one lowercase letter
        print("The password must contain at least one lowercase letter.")
        return False
    if not re.search(r"[A-Z]", password):  # at least one uppercase letter
        print("The password must contain at least one uppercase letter.")
        return False
    if not re.search(r"\d", password):  # at least one digit
        print("The password must contain at least one digit.")
        return False
    if not re.search(r"[~!@#$%&_\-+=`|\(){}[\]:;'<>,.?/]", password):  # at least one special character
        print("The password must contain at least one special character.")
        return False
    return True

def validate_login(conn, username, password):
    try:
        cursor = conn.cursor()
        
        # Fetch all users and decrypt usernames
        cursor.execute("SELECT id, username, password, role FROM users")
        users = cursor.fetchall()
        
        for user in users:
            decrypted_username = decrypt_data(user[1])  # Decrypt username
            
            if decrypted_username == username:
                # Compare hashed password
                hashed_password = hash_password(password)
                
                if user[2] == hashed_password:
                    return user[0], user[3]  # return user_id and role
        
        return None  # return None if login credentials are invalid
    except Exception as e:
        logging.error(f"Error during login: {e}")
        return None

# Add logging for user management
def add_user(conn, username, password, role, first_name, last_name):
    from database import insert_user  # Import only within the function
    user_id = insert_user(conn, username, password, role, first_name, last_name)
    if user_id:
        log_activity(username, "User added", f"Role: {role}, Name: {first_name} {last_name}")
    else:
        log_suspicious_activity(username, "Failed to add user", f"Role: {role}, Name: {first_name} {last_name}")

def delete_user(conn, user_id):
    from database import remove_user  # Import only within the function
    if remove_user(conn, user_id):
        log_activity("system", "User deleted", f"User ID: {user_id}")
    else:
        log_suspicious_activity("system", "Failed to delete user", f"User ID: {user_id}")

def username_exists(conn, username):
    """Check if a given username already exists in the database."""
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
    """Prompt the user to add a new user with a set role."""
    while True:
        username = input("Username: ")
        if not is_valid_username(username):
            print("Invalid username. Ensure the username meets the requirements.")
            continue

        # Check if the username already exists
        if username_exists(conn, username):
            print("This username already exists. Choose a different username.")
            continue
        break

    while True:
        password = input("Password: ")
        if not is_valid_password(password):
            print("Invalid password. Ensure the password meets the requirements.")
            continue
        break

    first_name = input("First Name: ")
    last_name = input("Last Name: ")

    # If default_role is not specified, ask the user to enter a role
    role = default_role if default_role else input("Role: ")

    encrypted_username = encrypt_data(username)  # Encrypt the username for storage
    hashed_password = hash_password(password)    # Hash the password for storage
    encrypted_first_name = encrypt_data(first_name)
    encrypted_last_name = encrypt_data(last_name)

    try:
        sql = """INSERT INTO users (username, password, role, first_name, last_name, registration_date)
                 VALUES (?, ?, ?, ?, ?, ?)"""
        cur = conn.cursor()
        cur.execute(sql, (encrypted_username, hashed_password, role, encrypted_first_name, encrypted_last_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        log_activity(username, "User added via prompt", f"Role: {role}, Name: {first_name} {last_name}")
        print(f"User {username} successfully added.")
    except Error as e:
        logging.error(f"Error adding user: {e}")
        log_suspicious_activity(username, "Failed to add user via prompt", f"Role: {role}, Name: {first_name} {last_name}")

def add_system_admin_prompt(conn):
    """Prompt the user to add a new system admin."""
    print("Add new system admin.")
    add_user_prompt(conn, default_role='system_admin')  # Use 'system_admin' as the default role

def add_consultant_prompt(conn):
    """Prompt the user to add a new consultant."""
    print("Add new consultant.")
    add_user_prompt(conn, default_role='consultant')  # Use 'consultant' as the default role

def update_password(conn, user_id):
    """Update the password of the current user."""
    while True:
        new_password = input("Enter your new password: ")
        if is_valid_password(new_password):
            break

    hashed_password = hash_password(new_password)

    try:
        # Retrieve the username of the current user
        sql_get_username = "SELECT username FROM users WHERE id=?"
        cur = conn.cursor()
        cur.execute(sql_get_username, (user_id,))
        row = cur.fetchone()

        if row:
            username = decrypt_data(row[0])  # Decrypt the username

            # Update the password for the found user
            sql_update = "UPDATE users SET password=? WHERE id=?"
            cur.execute(sql_update, (hashed_password, user_id))
            conn.commit()
            log_activity(username, "Password updated", "User updated their password")
            print(f"Password for user {username} successfully updated.")
        else:
            print("User not found.")
            logging.error("Failed to find user for password update.")

    except Error as e:
        logging.error(f"Error updating password: {e}")
        log_suspicious_activity("system", "Failed to update password", f"Attempted to update password for user ID {user_id} with error: {e}")

def list_users(conn):
    """Display a list of all users and their roles."""
    try:
        sql = "SELECT username, role FROM users"
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()

        for row in rows:
            try:
                decrypted_username = decrypt_data(row[0])  # Decrypt the username
                print(f"Username: {decrypted_username}, Role: {row[1]}")
            except Exception as e:
                logging.error(f"Error decrypting data: {row[0]}. Exception: {e}")
                print(f"Username: [hashed], Role: {row[1]}")
    except Error as e:
        logging.error(f"Error listing users: {e}")

def update_user_prompt(conn):
    """Prompt the user to update an existing user."""
    while True:
        username = input("Enter the current username of the user you want to update: ")
        if is_valid_username(username):
            break

    while True:
        new_username = input("New Username: ")
        if not is_valid_username(new_username):
            print("Invalid new username. Ensure the username meets the requirements.")
            continue
        if username_exists(conn, new_username):
            print("This new username already exists. Choose a different username.")
            continue
        break

    first_name = input("New First Name: ")
    last_name = input("New Last Name: ")

    try:
        # Fetch all users and decrypt usernames to find the correct user
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
            # Update the user based on user_id
            sql_update = "UPDATE users SET username=?, first_name=?, last_name=? WHERE id=?"
            cur.execute(sql_update, (encrypted_new_username, first_name, last_name, user_id))
            conn.commit()

            log_activity(username, "User updated", f"Username changed to {new_username}, Name updated to {first_name} {last_name}")
            print(f"User {username} successfully updated to {new_username}.")
        else:
            print(f"User {username} not found.")
            log_suspicious_activity(username, "Failed to update user", f"Attempted to update non-existent user {username}")
    except Error as e:
        logging.error(f"Error updating user: {e}")
        log_suspicious_activity(username, "Failed to update user", f"Attempted to update {username} with error: {e}")

def delete_user_prompt(conn):
    """Prompt the user to delete an existing user."""
    while True:
        username = input("Enter the username of the user you want to delete: ")
        if is_valid_username(username):
            break
    encrypted_username = None

    try:
        # Fetch all users and decrypt them to find who to delete
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
            print(f"User {username} successfully deleted.")
        else:
            print(f"User {username} not found.")
    except Error as e:
        logging.error(f"Error deleting user: {e}")
        log_suspicious_activity(username, "Failed to delete user", f"Attempted to delete {username}")

def reset_user_password(conn):
    """Reset the password of an existing user."""
    while True:
        username = input("Enter the username of the user whose password you want to reset: ")
        if is_valid_username(username):
            break

    while True:
        new_password = input("Enter the new password: ")
        if is_valid_password(new_password):
            break
    
    hashed_password = hash_password(new_password)

    try:
        # Fetch all users and decrypt usernames to find the correct user
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
            # Reset the password for the found user
            sql_update = "UPDATE users SET password=? WHERE id=?"
            cur.execute(sql_update, (hashed_password, user_id))
            conn.commit()
            log_activity(username, "Password reset", f"Password for {username} was reset")
            print(f"Password for user {username} successfully reset.")
        else:
            print(f"User {username} not found.")
            log_suspicious_activity(username, "Failed to reset password", f"Attempted to reset password for non-existent user {username}")
    except Error as e:
        logging.error(f"Error resetting password: {e}")
        log_suspicious_activity(username, "Failed to reset password", f"Attempted to reset password for {username} with error: {e}")

def update_admin_prompt(conn):
    """Prompt the user to update a system admin."""
    while True:
        username = input("Enter the current username of the system admin you want to update: ")
        if is_valid_username(username):
            break

    first_name = input("New First Name: ")
    last_name = input("New Last Name: ")

    while True:
        new_username = input("New Username: ")
        if not is_valid_username(new_username):
            print("Invalid new username. Ensure the username meets the requirements.")
            continue
        if username_exists(conn, new_username):
            print("This new username already exists. Choose a different username.")
            continue
        break

    try:
        # Fetch all users and decrypt usernames to find the correct user
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
                print("This function is only available for system admin accounts.")
                return

            # Update the system admin based on user_id
            sql_update = "UPDATE users SET username=?, first_name=?, last_name=? WHERE id=?"
            cur.execute(sql_update, (encrypted_new_username, encrypt_data(first_name), encrypt_data(last_name), user_id))
            conn.commit()

            log_activity(username, "System Admin updated", f"Username changed to {new_username}, Name updated to {first_name} {last_name}")
            print(f"System admin {username} successfully updated to {new_username}.")
        else:
            print(f"System admin {username} not found.")
            log_suspicious_activity(username, "Failed to update system admin", f"Attempted to update non-existent system admin {username}")
    except Error as e:
        logging.error(f"Error updating system admin: {e}")
        log_suspicious_activity(username, "Failed to update system admin", f"Attempted to update system admin {username} with error: {e}")

def delete_admin_prompt(conn):
    """Prompt the user to delete a system admin account."""
    while True:
        username = input("Enter the username of the system admin you want to delete: ")
        if is_valid_username(username):
            break
    encrypted_username = None

    try:
        # Fetch all users and decrypt them to find who to delete
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
                print("This function is only available for system admin accounts.")
                return

            sql_delete = "DELETE FROM users WHERE id=?"
            cur.execute(sql_delete, (user_id,))
            conn.commit()
            log_activity(username, "System Admin deleted", f"System Admin {username} was deleted")
            print(f"System admin {username} successfully deleted.")
        else:
            print(f"System admin {username} not found.")
    except Error as e:
        logging.error(f"Error deleting system admin: {e}")
        log_suspicious_activity(username, "Failed to delete system admin", f"Attempted to delete {username}")

def reset_admin_password_prompt(conn):
    """Prompt the superadmin to reset the password of a system admin."""
    while True:
        username = input("Enter the username of the system admin whose password you want to reset: ")
        if is_valid_username(username):
            break

    try:
        # Fetch all system admins and decrypt usernames to find the correct one
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
                new_password = input("Enter the new password: ")
                if is_valid_password(new_password):
                    break

            hashed_password = hash_password(new_password)

            # Reset the password for the found system admin
            sql_update = "UPDATE users SET password=? WHERE id=?"
            cur.execute(sql_update, (hashed_password, user_id))
            conn.commit()
            log_activity(username, "System Admin password reset", f"Password for system admin {username} was reset")
            print(f"Password for system admin {username} successfully reset.")
        else:
            print(f"System admin {username} not found.")
            log_suspicious_activity(username, "Failed to reset password for system admin", f"Attempted to reset password for non-existent system admin {username}")
    except Error as e:
        logging.error(f"Error resetting password for system admin: {e}")
        log_suspicious_activity(username, "Failed to reset password for system admin", f"Attempted to reset password for {username} with error: {e}")
