import binascii
import hashlib
import test_user
from database import Database
from server_security_utils import (
    authenticate,
    get_clients_public_key,
    sign_message_with_el_gamal,
    sign_and_encrypt_reponse,
    decrypt_user_message
)

from el_gamal_signature import ElGamalSignature
from config import SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT
import rsa

def get_user_encrypted_message():
    encrypted_user_message, signature = test_user.get_user_response()
    return decrypt_user_message(encrypted_user_message).decode().strip()

def send_to_user(msg):
    print(f"Sending: {msg}")

def send_to_user_encrypted(encrypted_message, signature):
    print("Sent encrypted message: ")
    send_to_user(encrypted_message)
    print("Sent signature: ")
    send_to_user(signature)

def send_user_options():
    menu = '''
    [1] for uploading new table entry
    [2] get entry from table
    '''
    print("\n----------------------- Sending Menu to User -----------------------")
    send_to_user_in_session(menu)

def send_to_user_in_session(msg):
    # In session == already has a twofish key
    encrypted_message, signature = sign_and_encrypt_reponse(msg)
    send_to_user_encrypted(encrypted_message, signature)

def print_encrypted_bytes(msg):
    blob_hex = "-".join([hex(m) for m in msg])
    print(f"Encrypted blob in hex = {blob_hex}")

def main():
    db = Database()

    username, password = test_user.get_user_credentials()
    print(f"username = {username}, password = {password}")

    if not authenticate(username, password):
        raise ValueError("Wrong Credentials!")
    
    print("\n--------------------- Successful Login!---------------------")
    print("\n--------------------- Generating first response!---------------------")
    
    # Successfull login
    user_public_key = get_clients_public_key(username)
    print(f"user_public_key (e, n) = {user_public_key}")

    twofish_key_encrypted_msg = rsa.encrypt(pk=user_public_key, plaintext=SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT)
    
    # El Gamal's implementation expects string and not a list
    twofish_key_encrypted_msg_signature = sign_message_with_el_gamal(twofish_key_encrypted_msg)

    print("\n--------------------- Send Back to User ---------------------")
    print("send the twofish key encrypted with rsa and its signature...")
    send_to_user_encrypted(twofish_key_encrypted_msg, twofish_key_encrypted_msg_signature)

    # From now on every message between the client and server will be encrypted
    print("\n--------------------- Sending Encrypted message using TwoFish with EL gamal Signature ---------------------")
    send_user_options()

    choice = get_user_encrypted_message()
    print(f"Received choice from user: {choice}")
    if choice == "1":
        id = get_user_encrypted_message()
        name = get_user_encrypted_message()
        db.add_row_to_db([id, name])

    elif choice == "2":
        id = get_user_encrypted_message()
        name = db.get_entry_by_id(id)
        send_to_user_in_session(name)


if __name__ == "__main__":
    main()