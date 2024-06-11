import shutil
import os
from datetime import datetime
import zipfile

def backup_database_and_logs(database_path):
    backup_dir = "backups"
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    # Maak een unieke bestandsnaam voor de backup
    backup_filename = f"{os.path.basename(database_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    backup_path = os.path.join(backup_dir, backup_filename)
    
    with zipfile.ZipFile(backup_path, 'w') as backup_zip:
        # Voeg de database toe aan de zip
        backup_zip.write(database_path, os.path.basename(database_path))
        
        # Voeg logbestanden toe aan de zip
        log_files = ["data/logs.csv", "data/encrypted_logs.csv", "data/system.log"]  # Voeg hier alle relevante logbestanden toe
        for log_file in log_files:
            if os.path.exists(log_file):
                backup_zip.write(log_file, os.path.basename(log_file))
            else:
                print(f"Logfile {log_file} could not be found, skipping.")

    print(f"Back-up succesfully created: {backup_path}")

def restore_database_from_backup(database_path):
    backup_dir = "backups"
    backup_file = input("Enter the name of the backup-file in (in the 'backups' directory): ")
    backup_path = os.path.join(backup_dir, backup_file)
    
    if os.path.exists(backup_path):
        with zipfile.ZipFile(backup_path, 'r') as backup_zip:
            # Extracteer alle bestanden naar de juiste locaties
            backup_zip.extractall()

            # Verplaats het geëxtraheerde databasebestand naar de juiste locatie
            extracted_db_path = os.path.join("data", os.path.basename(database_path))
            if os.path.exists(extracted_db_path):
                shutil.move(extracted_db_path, database_path)

            # Verplaats de geëxtraheerde logbestanden naar de juiste locaties
            for file_name in backup_zip.namelist():
                if file_name.startswith("logs") or file_name.startswith("system.log"):
                    extracted_file_path = os.path.join("data", os.path.basename(file_name))
                    shutil.move(extracted_file_path, os.path.join("data", file_name))
        
        print("Back-up succesfully recovered.")
    else:
        print("Backup file could not be found.")