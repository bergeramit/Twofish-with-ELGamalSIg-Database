from config import SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT
from twofish.twofish_ecb import TwofishECB
from server_security_utils import sign_and_encrypt_reponse, decrypt_message, signature_service

def get_user_response():
    print("\n------------------- Client Side --------------------")
    response = input("Respond with:")
    encrypted_message, encrypted_message_signature = sign_and_encrypt_reponse(response)
    print("\n------------------- End: Client Side --------------------")
    return encrypted_message, encrypted_message_signature

def get_user_credentials():
    print("\n------------------- Client Side --------------------")
    print("------------------- Enter Credentials --------------------")
    username = input("Username:")
    password = input("Password:")
    print("\n------------------- End: Client Side --------------------")
    return username, password

def print_encrypted_server_response(server_response, signature):
    plain_response = decrypt_message(server_response)
    print("\n------------------- Client Side --------------------")

    S_1, S_2 = signature
    if not signature_service.verify(S_1, S_2, server_response):
        raise ValueError("Signature Forged")
    
    print("\n------------------- Signature from Server: Validated --------------------")

    print("\n------------------- Got Response from Server --------------------")
    print("\n------------------- Decrypted Response --------------------")
    print(plain_response.strip())
    print("\n------------------- End: Client Side --------------------")
