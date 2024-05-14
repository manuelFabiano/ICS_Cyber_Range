#!/usr/bin/env python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import time


# Funzione per generare un timestamp univoco
def generate_timestamp():
    return str(int(time.time())).encode('utf-8')

def import_key_from_file(file_path):
    # Apre il file e legge la chiave
    with open(file_path, "rb") as f:
        key_data = f.read()
    # Importa la chiave utilizzando la libreria PyCryptodome
    key = RSA.import_key(key_data)
    return key

# Funzione per cifrare una chiave simmetrica con la chiave pubblica del destinatario e la firma
def encrypt_and_sign_symmetric_key(symmetric_key, recipient_public_key_file, private_key_file):
    # Genera un oggetto RSA con la chiave pubblica del destinatario
    recipient_public_key = import_key_from_file(recipient_public_key_file)
    # Crea un oggetto RSA in modalità OAEP con la chiave pubblica del destinatario
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    # Cifra la chiave simmetrica
    enc_symmetric_key = cipher_rsa.encrypt(symmetric_key)
    # Firma la chiave cifrata
    signature = sign_data(enc_symmetric_key, private_key_file)
    return enc_symmetric_key + signature

# Funzione per decifrare una chiave simmetrica con la chiave privata e verificare la firma
def decrypt_and_verify_symmetric_key(enc_symmetric_key, private_key_file, sender_public_key_file):
    # Estrae la chiave cifrata e la firma dalla stringa di byte
    signature = enc_symmetric_key[-256:]  # Estrae la firma
    enc_symmetric_key = enc_symmetric_key[:-256]  # Estrae la chiave cifrata
    # Verifica la firma della chiave cifrata
    is_verified = verify_signature(enc_symmetric_key, signature, sender_public_key_file)
    if not is_verified:
        print("Firma non verificata")
        return None, False
    # Genera un oggetto RSA con la chiave privata
    private_key = import_key_from_file(private_key_file)
    # Crea un oggetto RSA in modalità OAEP con la chiave privata
    cipher_rsa = PKCS1_OAEP.new(private_key)
    # Decifra la chiave simmetrica
    symmetric_key = cipher_rsa.decrypt(enc_symmetric_key)
    return symmetric_key, True
    


# Funzione per cifrare il testo segreto utilizzando AES in modalità CBC
def encrypt_secret_text_with_aes_cbc(secret_text, symmetric_key):
    # Genera un vettore di inizializzazione (IV) casuale
    iv = get_random_bytes(16)
    # Crea un oggetto AES in modalità CBC con la chiave simmetrica e il IV
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv=iv)
    # Cifra il testo segreto e aggiunge il padding se necessario
    ciphertext = cipher.encrypt(pad(secret_text, AES.block_size))
    # Restituisce il ciphertext e il IV
    return ciphertext, iv

# Funzione per decifrare il testo segreto utilizzando AES in modalità CBC
def decrypt_secret_text_with_aes_cbc(ciphertext, iv, symmetric_key):
    # Crea un oggetto AES in modalità CBC con la chiave simmetrica e il IV
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv=iv)
    # Decifra il ciphertext e rimuove il padding
    decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size)
    # Restituisce il testo decifrato
    return decrypted_text

# Funzione per firmare i dati
def sign_data(data, private_key_file):
    key = import_key_from_file(private_key_file)
    h = SHA256.new(data)
    signer = pkcs1_15.new(key)
    signature = signer.sign(h)
    return signature

# Funzione per verificare la firma
def verify_signature(data, signature, sender_public_key_file):
    key = import_key_from_file(sender_public_key_file)
    h = SHA256.new(data)
    verifier = pkcs1_15.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False    

# Funzione per cifrare il testo segreto, firmare il messaggio e restituire il messaggio cifrato con firma
def encrypt_and_sign_message(secret_text, symmetric_key, private_key):
    # Genera il timestamp
    timestamp = generate_timestamp()
    # Cifra il testo segreto con il timestamp utilizzando AES in modalità CBC
    ciphertext, iv = encrypt_secret_text_with_aes_cbc(secret_text, symmetric_key)
    # Firma il messaggio cifrato (timestamp + testo cifrato)
    signature = sign_data(timestamp + iv + ciphertext, private_key)
    # Combina i dati in un'unica stringa di byte
    encrypted_message = timestamp + iv + ciphertext + signature
    # Restituisce il messaggio cifrato con firma
    return encrypted_message

# Funzione per verificare il timestamp, decifrare il messaggio e verificare la firma
def decrypt_and_verify_message(encrypted_message, symmetric_key, sender_public_key):
    # Estrae i dati dalla stringa di byte
    timestamp = encrypted_message[:10]
    iv = encrypted_message[10:26]
    ciphertext = encrypted_message[26:-256]  # Rimuove la firma
    signature = encrypted_message[-256:]  # Estrae la firma
    # Verifica la firma del messaggio cifrato (timestamp + IV + testo cifrato)
    is_verified = verify_signature(timestamp + iv + ciphertext, signature, sender_public_key)
    if not is_verified:
        print("Firma non verificata")
        return None, False  # La firma non è valida, restituisci None per il testo segreto e False per la verifica della firma
    
    # Converte il timestamp in un numero intero
    timestamp_int = int(timestamp.decode('utf-8'))
    # Ottiene il timestamp corrente
    current_timestamp = int(time.time())
    if abs(current_timestamp - timestamp_int) > 30:
        print("Timestamp non valido")
        return None, False
    # Decifra il testo cifrato
    secret_text = decrypt_secret_text_with_aes_cbc(ciphertext, iv, symmetric_key)
    # Restituisce il testo segreto e True per la verifica della firma
    return secret_text, True 


