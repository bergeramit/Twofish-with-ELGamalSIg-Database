import rsa
from config import SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT, clients_db
from twofish.twofish_ecb import TwofishECB
from server_security_utils import (
    sign_and_encrypt_reponse,
    decrypt_message_in_session,
    signature_service,
    decrypt_fisrt_message
)

username = ''
twofish_key = ''

def get_user_response():
    global twofish_key
    print("\n------------------- Client Side --------------------")
    response = input("Respond with:")
    encrypted_message, encrypted_message_signature = sign_and_encrypt_reponse(response, twofish_key)
    print("\n------------------- End: Client Side --------------------")
    return encrypted_message, encrypted_message_signature

def get_user_credentials():
    global username
    print("\n------------------- Client Side --------------------")
    print("------------------- Enter Credentials --------------------")
    username = input("Username:")
    password = input("Password:")
    print("\n------------------- End: Client Side --------------------")
    return username, password

def validate_signature_from_server(server_response, signature):
    S_1, S_2 = signature
    if not signature_service.verify(S_1, S_2, server_response):
        raise ValueError("Signature Forged")
    print("\n------------------- Signature from Server: Validated --------------------")


def print_encrypted_server_response(server_response, signature):
    global twofish_key
    validate_signature_from_server(server_response, signature)
    plain_response = decrypt_message_in_session(server_response, twofish_key)
    print("\n------------------- Client Side --------------------")
    print("\n------------------- Got Response from Server --------------------")
    print("\n------------------- Decrypted Response --------------------")
    print(plain_response.strip())
    print("\n------------------- End: Client Side --------------------")

def get_first_response_from_server(server_response, signature):
    global username, twofish_key
    validate_signature_from_server(server_response, signature)
    twofish_key = decrypt_fisrt_message(server_response, clients_db[username].private_key)
    print(f"\n got key: {twofish_key}")
