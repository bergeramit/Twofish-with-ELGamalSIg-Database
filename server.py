import test_user
from database import Database
from server_security_utils import (
    authenticate,
    get_clients_public_key,
    sign_message_with_el_gamal,
    sign_and_encrypt_reponse,
    decrypt_message_in_session,
    convert_encrypted_message_to_string,
    signature_service
)

from config import SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT
import rsa

MENU = '''
    [1] for uploading new table entry
    [2] get entry from table
'''

def get_user_encrypted_message():
    encrypted_user_message, signature = test_user.get_user_response()
    
    S_1, S_2 = signature
    if not signature_service.verify(S_1, S_2, encrypted_user_message):
        raise ValueError("Signature Forged")
    
    print("\n----------------------- Client Signature Validated! -----------------------\n")
    return decrypt_message_in_session(encrypted_user_message, SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT).decode().strip()

def send_to_user(msg):
    print(f"{msg}")

def send_to_user_encrypted(encrypted_message, signature):
    print("\n----------------------- Sent to Client! -----------------------")
    print("----------------------- encrypted message -----------------------\n")
    send_to_user(encrypted_message)
    print("\n----------------------- signature -----------------------\n")
    send_to_user(signature)
    print("\n----------------------- End: Sent to Client! -----------------------\n")

def send_to_user_in_session(msg):
    # In session == already has a twofish key
    encrypted_message, signature = sign_and_encrypt_reponse(msg, SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT)
    send_to_user_encrypted(encrypted_message, signature)
    test_user.print_encrypted_server_response(encrypted_message, signature)

def main():
    db = Database()

    username, password = test_user.get_user_credentials()
    print("\n--------------------- Got Credentials from user ---------------------")
    print(f"username = {username}, password = {password}")

    if not authenticate(username, password):
        raise ValueError("Wrong Credentials!")
    
    print("--------------------- Successful Login ---------------------")
    print("--------------------- Generating first response ---------------------\n")
    
    # Successfull login
    user_public_key = get_clients_public_key(username)
    print(f"client's public key to use (e, n) = {user_public_key}")

    twofish_key_encrypted_msg = rsa.encrypt(pk=user_public_key, plaintext=SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT)
    twofish_key_encrypted_msg_string = convert_encrypted_message_to_string(twofish_key_encrypted_msg)
    # El Gamal's implementation expects string and not a list
    twofish_key_encrypted_msg_signature = sign_message_with_el_gamal(twofish_key_encrypted_msg_string)

    print("\n--------------------- Send Back to User ---------------------")
    print("send the twofish key encrypted with rsa and its signature...")
    send_to_user_encrypted(twofish_key_encrypted_msg_string, twofish_key_encrypted_msg_signature)
    test_user.get_first_response_from_server(twofish_key_encrypted_msg_string, twofish_key_encrypted_msg_signature)

    # From now on every message between the client and server will be encrypted
    print("\n--------------------- Begin Session Communication with Twofish key ---------------------")
    send_to_user_in_session(MENU)
    choice = get_user_encrypted_message()
    print(f"Received choice from user: {choice}")

    if choice == "1":
        send_to_user_in_session("Enter a name for the db entry")
        name = get_user_encrypted_message()
        send_to_user_in_session("Enter id for the db entry")
        id = get_user_encrypted_message()
        db.add_row_to_db([id, name])

    elif choice == "2":
        send_to_user_in_session("Enter id to retrive entry")
        id = get_user_encrypted_message()
        name = db.get_entry_by_id(id)
        send_to_user_in_session(name)


if __name__ == "__main__":
    main()