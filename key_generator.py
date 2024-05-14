#!/usr/bin/env python
from Crypto.PublicKey import RSA


def generate_and_save_keys(file_name):
    public_key_path = f"{file_name}_public_key.pem"
    private_key_path = f"{file_name}_private_key.pem"

    # Genera una nuova coppia di chiavi RSA
    key = RSA.generate(2048)
    # Estrae la chiave pubblica
    public_key = key.publickey().export_key()
    # Estrae la chiave privata
    private_key = key.export_key()

    # Scrive la chiave pubblica su file
    with open(public_key_path, 'wb') as f:
        f.write(public_key)
    print(f"Chiave pubblica salvata in: {public_key_path}")

    # Scrive la chiave privata su file
    with open(private_key_path, 'wb') as f:
        f.write(private_key)
    print(f"Chiave privata salvata in: {private_key_path}")

# Esempio di utilizzo
file_name = input("Inserisci il nome del file (senza estensione): ")
generate_and_save_keys(file_name)
