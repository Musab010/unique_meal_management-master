import sqlite3
import logging
from log import log_activity, log_suspicious_activity
import random
import re
from datetime import datetime
from encrypt_decrypt import encrypt_data, decrypt_data
from database import create_connection
from sqlite3 import Error

CITIES = [
    "Amsterdam", "Rotterdam", "The Hague", "Utrecht", "Eindhoven",
    "Tilburg", "Groningen", "Almere", "Breda", "Nijmegen"
]

def generate_membership_id():
    current_year = datetime.now().year
    short_year = str(current_year)[-2:]  # Shortened registration year, e.g., "23" for 2023
    random_digits = ''.join([str(random.randint(0, 9)) for _ in range(7)])  # 7 random digits
    base_id = short_year + random_digits

    checksum = sum(int(digit) for digit in base_id) % 10  # Calculate checksum
    membership_id = base_id + str(checksum)
    return membership_id

def validate_email(email):
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(regex, email) is not None

def validate_phone(phone):
    regex = r'^\+31-6-\d{8}$'
    return re.match(regex, phone) is not None

def add_member(conn, first_name, last_name, age, gender, weight, address, email, phone, membership_id):
    """Add a new member to the database."""
    encrypted_first_name = encrypt_data(first_name)
    encrypted_last_name = encrypt_data(last_name)
    encrypted_age = encrypt_data(str(age))
    encrypted_gender = encrypt_data(gender)
    encrypted_weight = encrypt_data(str(weight))
    encrypted_address = encrypt_data(address)
    encrypted_email = encrypt_data(email)
    encrypted_phone = encrypt_data(phone)
    encrypted_membership_id = encrypt_data(membership_id)

    try:
        sql = """INSERT INTO members (first_name, last_name, age, gender, weight, address, email, phone, registration_date, membership_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        cur = conn.cursor()
        cur.execute(sql, (encrypted_first_name, encrypted_last_name, encrypted_age, encrypted_gender, encrypted_weight, encrypted_address, encrypted_email, encrypted_phone, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), encrypted_membership_id))
        conn.commit()
        log_activity(membership_id, "Member added", f"Name: {first_name} {last_name}")
        return cur.lastrowid  # Return the ID of the added member
    except Error as e:
        logging.error(f"Error adding member: {e}")
        log_suspicious_activity(membership_id, "Failed to add member", f"Attempted to add member {first_name} {last_name}")
        return None

def add_member_prompt(conn):
    first_name = input("First Name: ")
    last_name = input("Last Name: ")

    while True:
        age_input = input("Age: ")
        if age_input.isdigit() and 0 < int(age_input) <= 120:
            age = int(age_input)
            break
        else:
            print("Invalid age. Enter a numeric value between 1 and 120.")

    while True:
        gender = input("Gender (M for male, F for female): ").strip().upper()
        if gender in ["M", "F"]:
            break
        else:
            print("Invalid gender. Enter 'M' for male or 'F' for female.")

    while True:
        weight_input = input("Weight (e.g., 72.5): ")
        try:
            weight = float(weight_input)
            if weight > 0:
                break
            else:
                print("Weight must be greater than 0.")
        except ValueError:
            print("Invalid weight. Enter a numeric value.")

    street = input("Street Name: ")
    house_number = input("House Number: ")
    
    while True:
        zip_code = input("Postal Code (format DDDDXX): ")
        if re.match(r'^\d{4}[A-Z]{2}$', zip_code):
            break
        print("Invalid postal code. Use the format DDDDXX.")

    print("Choose a city from the following list:")
    for i, city in enumerate(CITIES, start=1):
        print(f"{i}. {city}")
    
    while True:
        try:
            city_index = int(input("Enter the number of the city: "))
            if 1 <= city_index <= len(CITIES):
                city = CITIES[city_index - 1]
                break
            else:
                print(f"Enter a number between 1 and {len(CITIES)}.")
        except ValueError:
            print("Invalid input. Enter a numeric value.")

    address = f"{street} {house_number}, {zip_code} {city}"

    while True:
        email = input("Email: ")
        if validate_email(email):
            break
        print("Invalid email address.")
    
    while True:
        phone_input = input("Phone (format: +31-6-XXXXXXXX): ")
        if validate_phone(phone_input):
            phone = phone_input
            break
        print("Invalid phone number. Use the format +31-6-XXXXXXXX.")
    
    membership_id = generate_membership_id()
    member_id = add_member(conn, first_name, last_name, age, gender, weight, address, email, phone, membership_id)
    if member_id:
        print(f"Member {first_name} {last_name} successfully added with membership number {membership_id}.")
    else:
        print("Failed to add member.")

def search_member(conn, search_key):
    cur = conn.cursor()
    sql = """SELECT * FROM members WHERE
             first_name LIKE ? OR last_name LIKE ? OR address LIKE ? OR email LIKE ? OR phone LIKE ? OR membership_id LIKE ?"""
    search_key = f"%{search_key}%"
    cur.execute(sql, (search_key, search_key, search_key, search_key, search_key, search_key))
    rows = cur.fetchall()
    return rows

def search_member_prompt(conn):
    """Prompt the user to search for a member."""
    search_term = input("Enter the first name, last name, or membership number to search: ").strip()

    try:
        # Fetch all members
        sql_fetch_all = "SELECT first_name, last_name, membership_id, age, gender, weight, address, email, phone FROM members"
        cur = conn.cursor()
        cur.execute(sql_fetch_all)
        rows = cur.fetchall()

        found_members = []

        # Decrypt and search in relevant fields
        for row in rows:
            try:
                decrypted_first_name = decrypt_data(row[0])
                decrypted_last_name = decrypt_data(row[1])
                decrypted_membership_id = decrypt_data(row[2])
                decrypted_age = decrypt_data(row[3])  # Correctly decrypt
                decrypted_gender = decrypt_data(row[4])
                decrypted_weight = decrypt_data(row[5])  # Correctly decrypt
                decrypted_address = decrypt_data(row[6])
                decrypted_email = decrypt_data(row[7])
                decrypted_phone = decrypt_data(row[8])

                # Check if any of the fields match the search term
                if (search_term.lower() in decrypted_first_name.lower() or
                    search_term.lower() in decrypted_last_name.lower() or
                    search_term == decrypted_membership_id):
                    found_members.append({
                        "first_name": decrypted_first_name,
                        "last_name": decrypted_last_name,
                        "membership_id": decrypted_membership_id,
                        "age": decrypted_age,
                        "gender": decrypted_gender,
                        "weight": decrypted_weight,
                        "address": decrypted_address,
                        "email": decrypted_email,
                        "phone": decrypted_phone
                    })
            except Exception as e:
                logging.error(f"Error decrypting data: {e}")
                print(f"Error decrypting data for a member: {e}")

        # Display results
        if found_members:
            print("Found members:")
            for member in found_members:
                print(f"First Name: {member['first_name']}, Last Name: {member['last_name']}, Membership ID: {member['membership_id']}, Age: {member['age']}, Gender: {member['gender']}, Weight: {member['weight']}, Address: {member['address']}, Email: {member['email']}, Phone: {member['phone']}")
        else:
            print("No members found matching the search term.")
    except Error as e:
        logging.error(f"Error searching member: {e}")
        print("An error occurred while searching for members.")

def update_member(conn, membership_id):
    """Update member information based on membership ID."""
    print("Update member information.")

    # Fetch all members and decrypt to find the correct member
    sql_fetch_all = "SELECT id, first_name, last_name, membership_id FROM members"
    cur = conn.cursor()
    cur.execute(sql_fetch_all)
    rows = cur.fetchall()

    member_id = None

    # Find the member based on membership ID
    for row in rows:
        decrypted_membership_id = decrypt_data(row[3])
        if decrypted_membership_id == membership_id:
            member_id = row[0]
            break

    if not member_id:
        print(f"Member with membership ID {membership_id} not found.")
        return

    # Ask for new information
    first_name = input("New First Name: ")
    last_name = input("New Last Name: ")

    while True:
        age_input = input("New Age: ")
        if age_input.isdigit() and 0 < int(age_input) <= 120:
            age = int(age_input)
            break
        else:
            print("Invalid age. Enter a numeric value between 1 and 120.")

    while True:
        gender = input("New Gender (M for male, F for female): ").strip().upper()
        if gender in ["M", "F"]:
            break
        else:
            print("Invalid gender. Enter 'M' for male or 'F' for female.")

    while True:
        weight_input = input("New Weight (e.g., 72.5): ")
        try:
            weight = float(weight_input)
            if weight > 0:
                break
            else:
                print("Weight must be greater than 0.")
        except ValueError:
            print("Invalid weight. Enter a numeric value.")

    street = input("New Street Name: ")
    house_number = input("New House Number: ")

    while True:
        zip_code = input("New Postal Code (format DDDDXX): ")
        if re.match(r'^\d{4}[A-Z]{2}$', zip_code):
            break
        print("Invalid postal code. Use the format DDDDXX.")

    print("Choose a new city from the following list:")
    for i, city in enumerate(CITIES, start=1):
        print(f"{i}. {city}")

    while True:
        try:
            city_index = int(input("Enter the number of the new city: "))
            if 1 <= city_index <= len(CITIES):
                city = CITIES[city_index - 1]
                break
            else:
                print(f"Enter a number between 1 and {len(CITIES)}.")
        except ValueError:
            print("Invalid input. Enter a numeric value.")

    address = f"{street} {house_number}, {zip_code} {city}"

    while True:
        email = input("New Email: ")
        if validate_email(email):
            break
        print("Invalid email address.")

    while True:
        phone_input = input("New Phone (format: +31-6-XXXXXXXX): ")
        if validate_phone(phone_input):
            phone = phone_input
            break
        print("Invalid phone number. Use the format +31-6-XXXXXXXX.")

    # Update the member in the database
    sql_update = '''UPDATE members SET first_name=?, last_name=?, age=?, gender=?, weight=?, address=?, email=?, phone=? WHERE id=?'''
    cur.execute(sql_update, (
        encrypt_data(first_name), 
        encrypt_data(last_name), 
        encrypt_data(str(age)), 
        encrypt_data(gender), 
        encrypt_data(str(weight)), 
        encrypt_data(address), 
        encrypt_data(email), 
        encrypt_data(phone), 
        member_id
    ))
    conn.commit()
    print(f"Member {first_name} {last_name} successfully updated.")

def update_member_prompt(conn, member_id=None):
    """Prompt the user to update a member."""
    if member_id is None:
        member_id = input("Enter the membership ID of the member you want to update: ")
    update_member(conn, member_id)

def delete_member(conn, member_id):
    """Delete a member from the database based on membership ID."""
    # Fetch all members and decrypt the membership IDs to find the correct member
    sql_fetch_all = "SELECT id, membership_id FROM members"
    cur = conn.cursor()
    cur.execute(sql_fetch_all)
    rows = cur.fetchall()

    member_db_id = None

    for row in rows:
        decrypted_membership_id = decrypt_data(row[1])
        if decrypted_membership_id == member_id:
            member_db_id = row[0]
            break

    if member_db_id:
        sql_delete = 'DELETE FROM members WHERE id = ?'
        cur.execute(sql_delete, (member_db_id,))
        conn.commit()
        return cur.rowcount  # Return the number of deleted rows
    else:
        print(f"Member with membership ID {member_id} not found.")
        return 0

def delete_member_prompt(conn):
    """Prompt the user to delete a member."""
    member_id = input("Enter the membership ID of the member you want to delete: ")
    if delete_member(conn, member_id):
        print(f"Member with membership ID {member_id} successfully deleted.")
    else:
        print(f"Member with membership ID {member_id} not found.")
