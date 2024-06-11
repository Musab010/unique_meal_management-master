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
    "Amsterdam", "Rotterdam", "Den Haag", "Utrecht", "Eindhoven",
    "Tilburg", "Groningen", "Almere", "Breda", "Nijmegen"
]

def generate_membership_id():
    current_year = datetime.now().year
    short_year = str(current_year)[-2:]  # Verkorte registratiejaar, bv. "23" voor 2023
    random_digits = ''.join([str(random.randint(0, 9)) for _ in range(7)])  # 7 willekeurige cijfers
    base_id = short_year + random_digits

    checksum = sum(int(digit) for digit in base_id) % 10  # Controlegetal berekenen
    membership_id = base_id + str(checksum)
    return membership_id

def validate_email(email):
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(regex, email) is not None

def validate_phone(phone):
    regex = r'^\+31-6-\d{8}$'
    return re.match(regex, phone) is not None

def add_member(conn, first_name, last_name, age, gender, weight, address, email, phone, membership_id):
    """Voeg een nieuw lid toe aan de database."""
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
        return cur.lastrowid  # Retourneer het ID van het toegevoegde lid
    except Error as e:
        logging.error(f"Error adding member: {e}")
        log_suspicious_activity(membership_id, "Failed to add member", f"Attempted to add member {first_name} {last_name}")
        return None

def add_member_prompt(conn):
    first_name = input("Voornaam: ")
    last_name = input("Achternaam: ")

    while True:
        age_input = input("Leeftijd: ")
        if age_input.isdigit() and 0 < int(age_input) <= 120:
            age = int(age_input)
            break
        else:
            print("Ongeldige leeftijd. Voer een numerieke waarde in tussen 1 en 120.")

    while True:
        gender = input("Geslacht (M voor male, F voor female): ").strip().upper()
        if gender in ["M", "F"]:
            break
        else:
            print("Ongeldig geslacht. Voer 'M' voor male of 'F' voor female in.")

    while True:
        weight_input = input("Gewicht (bijv. 72.5): ")
        try:
            weight = float(weight_input)
            if weight > 0:
                break
            else:
                print("Gewicht moet groter zijn dan 0.")
        except ValueError:
            print("Ongeldig gewicht. Voer een numerieke waarde in.")

    street = input("Straatnaam: ")
    house_number = input("Huisnummer: ")
    
    while True:
        zip_code = input("Postcode (formaat DDDDXX): ")
        if re.match(r'^\d{4}[A-Z]{2}$', zip_code):
            break
        print("Ongeldige postcode. Gebruik het formaat DDDDXX.")

    print("Kies een stad uit de volgende lijst:")
    for i, city in enumerate(CITIES, start=1):
        print(f"{i}. {city}")
    
    while True:
        try:
            city_index = int(input("Voer het nummer van de stad in: "))
            if 1 <= city_index <= len(CITIES):
                city = CITIES[city_index - 1]
                break
            else:
                print(f"Voer een nummer in tussen 1 en {len(CITIES)}.")
        except ValueError:
            print("Ongeldige invoer. Voer een numerieke waarde in.")

    address = f"{street} {house_number}, {zip_code} {city}"

    while True:
        email = input("Email: ")
        if validate_email(email):
            break
        print("Ongeldig emailadres.")
    
    while True:
        phone_input = input("Telefoon (formaat: +31-6-XXXXXXXX): ")
        if validate_phone(phone_input):
            phone = phone_input
            break
        print("Ongeldig telefoonnummer. Gebruik het formaat +31-6-XXXXXXXX.")
    
    membership_id = generate_membership_id()
    member_id = add_member(conn, first_name, last_name, age, gender, weight, address, email, phone, membership_id)
    if member_id:
        print(f"Lid {first_name} {last_name} succesvol toegevoegd met lidnummer {membership_id}.")
    else:
        print("Lid toevoegen mislukt.")

def search_member(conn, search_key):
    cur = conn.cursor()
    sql = """SELECT * FROM members WHERE
             first_name LIKE ? OR last_name LIKE ? OR address LIKE ? OR email LIKE ? OR phone LIKE ? OR membership_id LIKE ?"""
    search_key = f"%{search_key}%"
    cur.execute(sql, (search_key, search_key, search_key, search_key, search_key, search_key))
    rows = cur.fetchall()
    return rows

def search_member_prompt(conn):
    """Prompt de gebruiker om een lid te zoeken."""
    search_term = input("Voer de voornaam, achternaam of lidnummer in om te zoeken: ").strip()

    try:
        # Haal alle leden op
        sql_fetch_all = "SELECT first_name, last_name, membership_id, age, gender, weight, address, email, phone FROM members"
        cur = conn.cursor()
        cur.execute(sql_fetch_all)
        rows = cur.fetchall()

        found_members = []

        # Ontsleutel en zoek in de relevante velden
        for row in rows:
            try:
                decrypted_first_name = decrypt_data(row[0])
                decrypted_last_name = decrypt_data(row[1])
                decrypted_membership_id = decrypt_data(row[2])
                decrypted_age = decrypt_data(row[3])  # Correct ontsleutelen
                decrypted_gender = decrypt_data(row[4])
                decrypted_weight = decrypt_data(row[5])  # Correct ontsleutelen
                decrypted_address = decrypt_data(row[6])
                decrypted_email = decrypt_data(row[7])
                decrypted_phone = decrypt_data(row[8])

                # Controleer of een van de velden overeenkomt met de zoekterm
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
                # Optionally, print a message if you want to notify about decryption issues
                print(f"Fout bij het ontsleutelen van gegevens voor een lid: {e}")

        # Resultaten weergeven
        if found_members:
            print("Gevonden leden:")
            for member in found_members:
                print(f"Voornaam: {member['first_name']}, Achternaam: {member['last_name']}, Lidnummer: {member['membership_id']}, Leeftijd: {member['age']}, Geslacht: {member['gender']}, Gewicht: {member['weight']}, Adres: {member['address']}, Email: {member['email']}, Telefoon: {member['phone']}")
        else:
            print("Geen leden gevonden die overeenkomen met de zoekterm.")
    except Error as e:
        logging.error(f"Error searching member: {e}")
        print("Er is een fout opgetreden bij het zoeken naar leden.")

def update_member(conn, membership_id):
    """Update de informatie van een lid op basis van het lidmaatschapsnummer."""
    print("Update informatie van lid.")

    # Eerst alle leden ophalen en decrypten
    sql_fetch_all = "SELECT id, first_name, last_name, membership_id FROM members"
    cur = conn.cursor()
    cur.execute(sql_fetch_all)
    rows = cur.fetchall()

    member_id = None

    # Zoek het lid op basis van het lidmaatschapsnummer
    for row in rows:
        decrypted_membership_id = decrypt_data(row[3])
        if decrypted_membership_id == membership_id:
            member_id = row[0]
            break

    if not member_id:
        print(f"Lid met lidmaatschapsnummer {membership_id} niet gevonden.")
        return

    # Vraag om de nieuwe informatie
    first_name = input("Nieuwe voornaam: ")
    last_name = input("Nieuwe achternaam: ")

    while True:
        age_input = input("Nieuwe leeftijd: ")
        if age_input.isdigit() and 0 < int(age_input) <= 120:
            age = int(age_input)
            break
        else:
            print("Ongeldige leeftijd. Voer een numerieke waarde in tussen 1 en 120.")

    while True:
        gender = input("Nieuw geslacht (M voor male, F voor female): ").strip().upper()
        if gender in ["M", "F"]:
            break
        else:
            print("Ongeldig geslacht. Voer 'M' voor male of 'F' voor female in.")

    while True:
        weight_input = input("Nieuw gewicht (bijv. 72.5): ")
        try:
            weight = float(weight_input)
            if weight > 0:
                break
            else:
                print("Gewicht moet groter zijn dan 0.")
        except ValueError:
            print("Ongeldig gewicht. Voer een numerieke waarde in.")

    street = input("Nieuwe straatnaam: ")
    house_number = input("Nieuw huisnummer: ")

    while True:
        zip_code = input("Nieuwe postcode (formaat DDDDXX): ")
        if re.match(r'^\d{4}[A-Z]{2}$', zip_code):
            break
        print("Ongeldige postcode. Gebruik het formaat DDDDXX.")

    print("Kies een nieuwe stad uit de volgende lijst:")
    for i, city in enumerate(CITIES, start=1):
        print(f"{i}. {city}")

    while True:
        try:
            city_index = int(input("Voer het nummer van de nieuwe stad in: "))
            if 1 <= city_index <= len(CITIES):
                city = CITIES[city_index - 1]
                break
            else:
                print(f"Voer een nummer in tussen 1 en {len(CITIES)}.")
        except ValueError:
            print("Ongeldige invoer. Voer een numerieke waarde in.")

    address = f"{street} {house_number}, {zip_code} {city}"

    while True:
        email = input("Nieuwe email: ")
        if validate_email(email):
            break
        print("Ongeldig emailadres.")

    while True:
        phone_input = input("Nieuwe telefoon (formaat: +31-6-XXXXXXXX): ")
        if validate_phone(phone_input):
            phone = phone_input
            break
        print("Ongeldig telefoonnummer. Gebruik het formaat +31-6-XXXXXXXX.")

    # Update het lid in de database
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
    print(f"Lid {first_name} {last_name} succesvol bijgewerkt.")

def update_member_prompt(conn, member_id=None):
    """Prompt de gebruiker om een lid bij te werken."""
    if member_id is None:
        member_id = input("Voer het lidmaatschapsnummer in van het lid dat je wilt bijwerken: ")
    update_member(conn, member_id)

def delete_member(conn, member_id):
    """Verwijder een lid uit de database op basis van het lidmaatschapsnummer."""
    # Haal alle leden op en decrypt de lidmaatschapsnummers om het juiste lid te vinden
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
        return cur.rowcount  # Geeft het aantal verwijderde rijen terug
    else:
        print(f"Lid met lidmaatschapsnummer {member_id} is niet gevonden.")
        return 0

def delete_member_prompt(conn):
    """Prompt de gebruiker om een lid te verwijderen."""
    member_id = input("Voer het lidmaatschapsnummer in van het lid dat je wilt verwijderen: ")
    if delete_member(conn, member_id):
        print(f"Lid met lidmaatschapsnummer {member_id} is succesvol verwijderd.")
    else:
        print(f"Lid met lidmaatschapsnummer {member_id} is niet gevonden.")
