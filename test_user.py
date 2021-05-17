import rsa
import logging
from config import SERVER_TWOFISH_SYMETRIC_KEY_PLAINTEXT, clients_db
from twofish.twofish_ecb import TwofishECB
from security_utils import (
    sign_and_encrypt_reponse,
    decrypt_message_in_session,
    signature_service,
    decrypt_first_message
)

class TestUser:
    USERNAME = ''
    TWOFISH_KEY = ''

    @classmethod
    def get_user_response(cls):
        global twofish_key
        logging.info("Client Side")
        response = input("Respond with:")
        encrypted_message, encrypted_message_signature = sign_and_encrypt_reponse(response, cls.TWOFISH_KEY)
        logging.info("End: Client Side")
        return encrypted_message, encrypted_message_signature

    @classmethod
    def get_user_credentials(cls):
        global username
        logging.info("Client Side")
        logging.info("Enter Credentials")
        cls.USERNAME = input("Username:")
        password = input("Password:")
        logging.info("End: Client Side")
        return cls.USERNAME, password

    @classmethod
    def validate_signature_from_server(cls, server_response, signature):
        S_1, S_2 = signature
        if not signature_service.verify(S_1, S_2, server_response):
            raise ValueError("Signature Forged")
        logging.debug("Signature from Server: Validated")

    @classmethod
    def print_encrypted_server_response(cls, server_response, signature):
        global twofish_key
        cls.validate_signature_from_server(server_response, signature)
        plain_response = decrypt_message_in_session(server_response, cls.TWOFISH_KEY)
        logging.info("Client Side")
        logging.info("Got Response from Server")
        logging.debug("Decrypted Response")
        logging.info(plain_response.strip())
        logging.info("End: Client Side")

    @classmethod
    def get_first_response_from_server(cls, server_response, signature):
        global username, twofish_key
        logging.info("Client Side")
        cls.validate_signature_from_server(server_response, signature)
        cls.TWOFISH_KEY = decrypt_first_message(server_response, clients_db[cls.USERNAME].private_key)
        logging.debug(f"Got Twofish key: {cls.TWOFISH_KEY}")
        logging.info("End: Client Side")
