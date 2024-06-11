import sqlite3
from datetime import datetime
from encrypt_decrypt import encrypt_data, decrypt_data
from utils import hash_password  # Gebruik de hash_password-functie vanuit utils
import logging
from sqlite3 import Error

def create_connection(db_file):
    """Maak een databaseverbinding naar het SQLite databasebestand."""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(f"SQLite verbinding is succesvol: {sqlite3.version}")
    except Error as e:
        print(e)
    return conn

def create_tables(conn):
    """Maak de benodigde tabellen aan."""
    try:
        sql_create_users_table = """CREATE TABLE IF NOT EXISTS users (
                                    id integer PRIMARY KEY,
                                    username text NOT NULL UNIQUE,  # Voeg UNIQUE constraint toe
                                    password text NOT NULL,
                                    role text NOT NULL,
                                    first_name text NOT NULL,
                                    last_name text NOT NULL,
                                    registration_date text NOT NULL
                                );"""

        sql_create_members_table = """CREATE TABLE IF NOT EXISTS members (
                                      id integer PRIMARY KEY,
                                      first_name text NOT NULL,
                                      last_name text NOT NULL,
                                      age integer,
                                      gender text,
                                      weight real,
                                      address text,
                                      email text,
                                      phone text,
                                      registration_date text NOT NULL,
                                      membership_id text NOT NULL
                                  );"""

        sql_create_logs_table = """CREATE TABLE IF NOT EXISTS logs (
                                   id integer PRIMARY KEY,
                                   date text NOT NULL,
                                   time text NOT NULL,
                                   username text,
                                   description text NOT NULL,
                                   additional_info text,
                                   suspicious text NOT NULL
                               );"""

        cursor = conn.cursor()
        cursor.execute(sql_create_users_table)
        cursor.execute(sql_create_members_table)
        cursor.execute(sql_create_logs_table)
    except Error as e:
        print(e)

def add_super_admin(conn):
    """Voeg de super admin gebruiker toe als deze nog niet bestaat."""
    try:
        hashed_password = hash_password("Admin_123?")  # Hash het wachtwoord

        # Controleer of er al een super_admin bestaat op basis van de rol
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE role='super_admin'")
        if cur.fetchone():
            print("Super admin bestaat al.")
            return

        # Voeg super_admin toe als deze nog niet bestaat
        encrypted_username = encrypt_data("super_admin")  # Versleutel de gebruikersnaam
        sql = """INSERT INTO users (username, password, role, first_name, last_name, registration_date)
                 VALUES (?, ?, 'super_admin', 'Super', 'Admin', ?)"""
        cur.execute(sql, (encrypted_username, hashed_password, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        print("Super admin toegevoegd.")
    except Error as e:
        print(e)

def insert_user(conn, username, password, role, first_name, last_name):
    """Voeg een nieuwe gebruiker toe aan de database."""
    encrypted_username = encrypt_data(username)  # Encrypt de gebruikersnaam
    hashed_password = hash_password(password)    # Hash het wachtwoord voor opslag
    encrypted_first_name = encrypt_data(first_name)
    encrypted_last_name = encrypt_data(last_name)

    try:
        sql = """INSERT INTO users (username, password, role, first_name, last_name, registration_date)
                 VALUES (?, ?, ?, ?, ?, ?)"""
        cur = conn.cursor()
        cur.execute(sql, (encrypted_username, hashed_password, role, encrypted_first_name, encrypted_last_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        return cur.lastrowid  # Retourneer het ID van de toegevoegde gebruiker
    except sqlite3.IntegrityError as e:
        logging.error(f"Error adding user: {e}")
        return None
    except Exception as e:
        logging.error(f"Error adding user: {e}")
        return None

def remove_user(conn, user_id):
    """Verwijder een gebruiker uit de database op basis van het user_id."""
    try:
        sql = "DELETE FROM users WHERE id=?"
        cur = conn.cursor()
        cur.execute(sql, (user_id,))
        conn.commit()
        return cur.rowcount  # Geeft het aantal verwijderde rijen terug
    except Error as e:
        logging.error(f"Error deleting user: {e}")
        return 0


