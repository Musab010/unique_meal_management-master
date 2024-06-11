import logging
from sqlite3 import connect
from datetime import datetime
from user import validate_login, add_user_prompt, add_system_admin_prompt, add_consultant_prompt, update_password, list_users, update_user_prompt, delete_user_prompt, reset_user_password, delete_admin_prompt, update_admin_prompt, reset_admin_password_prompt
from member import add_member_prompt, search_member_prompt, update_member_prompt, delete_member_prompt
from log import log_activity, log_suspicious_activity, get_suspicious_logs, decrypt_log_file
from database import create_connection, create_tables, add_super_admin
from backup import backup_database_and_logs,restore_database_from_backup

# Logging configuratie
logging.basicConfig(filename='data/system.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main_menu(role):
    print("\n===================================")
    print("Welkom bij Unique Meal Management System")
    print("===================================")
    if role == 'super_admin':
        print("1. Voeg systeembeheerder toe (A/a)")
        print("2. Voeg consultant toe (C/c)")
        print("3. Update systeembeheerder (U/u)")
        print("4. Verwijder systeembeheerder (D/d)")
        print("5. Reset wachtwoord van systeembeheerder (R/r)")
    if role in ['super_admin', 'system_admin']:
        print("6. Bekijk gebruikers en rollen (V/v)")
        print("7. Wijzig consultant account (U/u)")
        print("8. Verwijder consultant account (D/d)")
        print("9. Reset consultant wachtwoord (R/r)")
        print("10. Maak back-up (B/b)")
        print("11. Herstel back-up (H/h)")
        print("12. Bekijk logs (L/l)")
        print("13. Registreer nieuw lid (N/n)")
        print("14. Zoek lid (S/s)")
        print("15. Update lid (U/u)")
        print("16. Verwijder lid (D/d)")
    if role == 'consultant':
        print("13. Registreer nieuw lid (N/n)")
        print("14. Zoek lid (S/s)")
        print("15. Update lid (U/u)")
        print("16. Verwijder lid (D/d)")
    if role == 'member':
        print("Profielbeheer (alleen indien toegestaan)")
    print("17. Update wachtwoord (P/p)")
    print("18. Afsluiten (Q/q)")
    print("===================================")
    choice = input("Voer uw keuze in: ").strip().lower()
    return choice


def login_prompt(conn, max_attempts=3):
    attempts = 0
    while attempts < max_attempts:
        username = input("Gebruikersnaam: ")
        password = input("Wachtwoord: ")
        
        result = validate_login(conn, username, password)
        
        if result:
            user_id, role = result
            log_activity(username, "Logged in")
            logging.info("Login successful.")
            return user_id, role
        else:
            log_suspicious_activity(username, "Failed login attempt", f"Attempt {attempts + 1}")
            logging.info(f"Failed login attempt {attempts + 1} for username: {username}")
            print("Ongeldige inloggegevens. Probeer opnieuw of sluit af.")
            opnieuw_proberen = input("Wilt u opnieuw proberen? (j/n): ").lower()
            if opnieuw_proberen == 'n':
                log_activity(username, "User chose to exit after failed login attempts")
                print("Afsluiten...")
                exit()
        
        attempts += 1
        if attempts >= max_attempts:
            log_suspicious_activity(username, "Too many failed login attempts", f"Total attempts: {max_attempts}")
            print("Te veel mislukte inlogpogingen. Afsluiten...")
            exit()


def main():
    database = "data/unique_meal.db"
    conn = create_connection(database)
    if conn is not None:
        create_tables(conn)
        add_super_admin(conn)

    user_id, role = login_prompt(conn)
    if user_id is None:
        return

    if role in ['super_admin', 'system_admin']:
        suspicious_logs = get_suspicious_logs()
        if suspicious_logs:
            print("Er zijn ongelezen verdachte activiteiten!")
            for log_entry in suspicious_logs:
                print(f"{log_entry[0]} - {log_entry[1]} {log_entry[2]} - {log_entry[3]}: {log_entry[4]} - {log_entry[5]}")

    while True:
        choice = main_menu(role)
        if choice in ['a', '1'] and role == 'super_admin':
            add_user_prompt(conn, default_role='system_admin')
        elif choice in ['c', '2'] and role == 'super_admin':
            add_user_prompt(conn, default_role='consultant')
        elif choice in ['u', '3'] and role == 'super_admin':
            update_admin_prompt(conn)
        elif choice in ['d', '4'] and role == 'super_admin':
            delete_admin_prompt(conn)
        elif choice in ['r', '5'] and role == 'super_admin':
            reset_admin_password_prompt(conn)
        elif choice in ['v', '6'] and role in ['super_admin', 'system_admin']:
            list_users(conn)
        elif choice in ['u', '7'] and role in ['super_admin', 'system_admin']:
            update_user_prompt(conn)
        elif choice in ['d', '8'] and role in ['super_admin', 'system_admin']:
            delete_user_prompt(conn)
        elif choice in ['r', '9'] and role in ['super_admin', 'system_admin']:
            reset_user_password(conn)
        elif choice in ['b', '10'] and role in ['super_admin', 'system_admin']:
            backup_database_and_logs(database)
        elif choice in ['h', '11'] and role in ['super_admin', 'system_admin']:
            restore_database_from_backup(database)
        elif choice in ['l', '12'] and role in ['super_admin', 'system_admin']:
            logs = decrypt_log_file()
            for log_entry in logs:
                print(f"{log_entry[0]} - {log_entry[1]} {log_entry[2]} - {log_entry[3]}: {log_entry[4]} - {log_entry[5]} - Verdacht: {log_entry[6]}")
        elif choice in ['n', '13'] and role in ['super_admin', 'system_admin', 'consultant']:
            add_member_prompt(conn)
        elif choice in ['s', '14'] and role in ['super_admin', 'system_admin', 'consultant']:
            search_member_prompt(conn)
        elif choice in ['u', '15'] and role in ['super_admin', 'system_admin', 'consultant']:
            member_id = input("Voer lidmaatschapsnummer in: ")
            update_member_prompt(conn, member_id)
        elif choice in ['d', '16'] and role in ['super_admin', 'system_admin']:
            delete_member_prompt(conn)
        elif choice in ['p', '17']:
            update_password(conn, user_id)
        elif choice in ['q', '18']:
            print("Afsluiten...")
            break
        else:
            print("Ongeldige keuze. Probeer opnieuw.")

    conn.close()

if __name__ == '__main__':
    main()
