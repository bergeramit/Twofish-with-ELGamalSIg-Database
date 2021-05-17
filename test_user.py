from config import SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT
from el_gamal_signature import ElGamalSignature
from twofish.twofish_ecb import TwofishECB
from server_security_utils import sign_and_encrypt_reponse

def get_user_response():
    print("\n------------------- Client Side --------------------")
    response = input("Respond with:")
    encrypted_message, encrypted_message_signature = sign_and_encrypt_reponse(response)
    return encrypted_message, encrypted_message_signature


def get_user_credentials():
    username = input("Username:")
    password = input("Password:")
    return username, password

