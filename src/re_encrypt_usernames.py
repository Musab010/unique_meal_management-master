import sqlite3
from encrypt_decrypt import encrypt_data, decrypt_data, hash_username

def re_encrypt_usernames(db_file):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Haal alle gebruikers op
        cursor.execute("SELECT id, username FROM users")
        users = cursor.fetchall()

        for user in users:
            user_id = user[0]
            username = user[1]

            try:
                # Probeer de gebruikersnaam te ontsleutelen (als het al versleuteld is)
                decrypted_username = decrypt_data(username)
            except Exception as e:
                decrypted_username = username  # Het was waarschijnlijk al niet versleuteld

            # Versleutel de gebruikersnaam opnieuw
            encrypted_username = encrypt_data(decrypted_username)

            # Update de gebruikersnaam in de database
            cursor.execute("UPDATE users SET username=? WHERE id=?", (encrypted_username, user_id))

        conn.commit()
        print("Gebruikersnamen succesvol opnieuw versleuteld.")
    except Exception as e:
        print(f"Fout bij het opnieuw versleutelen van gebruikersnamen: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    re_encrypt_usernames("data/unique_meal.db")
